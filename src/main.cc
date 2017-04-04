#include <configuration.hh>
#include <engine.hh>
#include <reporter.hh>
#include <writer.hh>
#include <collector.hh>
#include <filter.hh>
#include <output-handler.hh>
#include <file-parser.hh>
#include <solib-handler.hh>
#include <utils.hh>

#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>

#include "merge-parser.hh"
#include "writers/html-writer.hh"
#include "writers/json-writer.hh"
#include "writers/coveralls-writer.hh"
#include "writers/cobertura-writer.hh"
#include "writers/sonarqube-xml-writer.hh"

using namespace kcov;

static IEngine *g_engine;
static IOutputHandler *g_output;
static ICollector *g_collector;
static IReporter *g_reporter;
static ISolibHandler *g_solibHandler;
static IFilter *g_filter;
static IFilter *g_basicFilter;

static void do_cleanup()
{
	delete g_collector;
	delete g_output;
	delete g_reporter;
	delete g_solibHandler; // Before the engine since a SIGTERM is sent to the thread
	delete g_engine;
	delete g_filter;
	delete g_basicFilter;
}

static void ctrlc(int sig)
{
	// Forward the signal to the traced program
	g_engine->kill(sig);
}

static void daemonize(void)
{
	pid_t child;
	int res;

	IConfiguration &conf = IConfiguration::getInstance();
	std::string fifoName = conf.keyAsString("target-directory") + "/done.fifo";

	unlink(fifoName.c_str());
	res = mkfifo(fifoName.c_str(), 0600);

	panic_if(res < 0,
			"Can't create FIFO");

	child = fork();

	if (child < 0) {
		panic("Fork failed?\n");
	} else if (child == 0) {
		child = fork();

		if (child < 0) {
			panic("Fork failed?\n");
		} else if (child > 0) {
			// Second parent
			exit(0);
		}
	} else {
		// Parent
		FILE *fp;
		char buf[255];
		char *endp;
		char *p;
		unsigned long out;

		fp = fopen(fifoName.c_str(), "r");
		panic_if (!fp,
				"Can't open FIFO");
		p = fgets(buf, sizeof(buf), fp);
		panic_if (!p,
				"Can't read FIFO");


		out = strtoul(p, &endp, 10);
		if (p == endp)
			out = 0;

		exit(out);
	}
}

// Return the number of metadata directories in the kcov output path
unsigned int countMetadata()
{
	IConfiguration &conf = IConfiguration::getInstance();
	std::string base = conf.keyAsString("out-directory");
	DIR *dir;
	struct dirent *de;

	dir = ::opendir(base.c_str());
	if (!dir)
		return 0;

	unsigned int out = 0;

	// Count metadata directories
	for (de = ::readdir(dir); de; de = ::readdir(dir)) {
		std::string cur = base + de->d_name + "/metadata";

		// ... except for the current coveree
		if (de->d_name == conf.keyAsString("binary-name"))
			continue;

		DIR *metadataDir;
		struct dirent *de2;

		metadataDir = ::opendir(cur.c_str());
		if (!metadataDir)
			continue;

		// Count metadata files
		unsigned int datum = 0;
		for (de2 = ::readdir(metadataDir); de2; de2 = ::readdir(metadataDir)) {
			if (de2->d_name[0] == '.')
				continue;

			datum++;
		}
		out += !!datum;
		::closedir(metadataDir);
	}
	::closedir(dir);

	return out;
}

/*
 * Run in merge-mode, i.e., run kcov on previously generated coverage runs and
 * create a common merged output from them.
 */
static int runMergeMode()
{
	IFilter &filter = IFilter::create();
	IFilter &basicFilter = IFilter::createBasic();
	IReporter &reporter = IReporter::createDummyReporter();
	IOutputHandler &output = IOutputHandler::create(reporter, NULL);
	IConfiguration &conf = IConfiguration::getInstance();

	const std::string &base = output.getBaseDirectory();
	const std::string &out = output.getOutDirectory();

	IMergeParser &mergeParser = createMergeParser(reporter,	base, out, filter);
	IReporter &mergeReporter = IReporter::create(mergeParser, mergeParser, basicFilter);
	IWriter &mergeHtmlWriter = createHtmlWriter(mergeParser, mergeReporter,
			base, base + "/kcov-merged", conf.keyAsString("merged-name"), true);
	IWriter &mergeJsonWriter = createJsonWriter(mergeParser, mergeReporter,
			base + "kcov-merged/coverage.json");
	IWriter &mergeCoberturaWriter = createCoberturaWriter(mergeParser, mergeReporter,
			base + "kcov-merged/cobertura.xml");
	IWriter &mergeSonarqubeWriter = createSonarqubeWriter(mergeParser, mergeReporter,
			base + "kcov-merged/sonarqube.xml");
	IWriter &mergeCoverallsWriter = createCoverallsWriter(mergeParser, mergeReporter);
	(void)mkdir(fmt("%s/kcov-merged", base.c_str()).c_str(), 0755);

	output.registerWriter(mergeParser);
	output.registerWriter(mergeHtmlWriter);
	output.registerWriter(mergeJsonWriter);
	output.registerWriter(mergeCoberturaWriter);
	output.registerWriter(mergeSonarqubeWriter);
	output.registerWriter(mergeCoverallsWriter);

	output.start();
	output.stop();

	mergeReporter.writeCoverageDatabase();
	delete &output;

	return 0;
}

static int runKcov(IConfiguration::RunMode_t runningMode)
{
	IConfiguration &conf = IConfiguration::getInstance();

	std::string file = conf.keyAsString("binary-path") + conf.keyAsString("binary-name");
	IFileParser *parser = IParserManager::getInstance().matchParser(file);
	if (!parser) {
		error("Can't find or open %s\n", file.c_str());
		return 1;
	}

	// Match and create an engine
	IEngineFactory::IEngineCreator &engineCreator = IEngineFactory::getInstance().matchEngine(file);
	IEngine *engine = engineCreator.create(*parser);
	if (!engine) {
		conf.printUsage();
		return 1;
	}

	IFilter &filter = IFilter::create();
	IFilter &basicFilter = IFilter::createBasic();

	ICollector &collector = ICollector::create(*parser, *engine, filter);
	IReporter &reporter = IReporter::create(*parser, collector, filter);
	IOutputHandler &output = IOutputHandler::create(reporter, &collector);
	ISolibHandler &solibHandler = createSolibHandler(*parser, collector);

	parser->addFile(file);

	// Register writers
	if (runningMode != IConfiguration::MODE_COLLECT_ONLY) {
		const std::string &base = output.getBaseDirectory();
		const std::string &out = output.getOutDirectory();

		IWriter &htmlWriter = createHtmlWriter(*parser, reporter,
				base, out, conf.keyAsString("binary-name"));
		IWriter &jsonWriter = createJsonWriter(*parser, reporter,
				out + "/coverage.json");
		IWriter &coberturaWriter = createCoberturaWriter(*parser, reporter,
				out + "/cobertura.xml");
		IWriter &sonarqubeWriter = createSonarqubeWriter(*parser, reporter,
				out + "/sonarqube.xml");

		// The merge parser is both a parser, a writer and a collector (!)
		IMergeParser &mergeParser = createMergeParser(reporter,	base, out, filter);
		IReporter &mergeReporter = IReporter::create(mergeParser, mergeParser, basicFilter);
		IWriter &mergeHtmlWriter = createHtmlWriter(mergeParser, mergeReporter,
				base, base + "/kcov-merged", conf.keyAsString("merged-name"), false);
		IWriter &mergeJsonWriter = createJsonWriter(mergeParser, mergeReporter,
				base + "kcov-merged/coverage.json");
		IWriter &mergeCoberturaWriter = createCoberturaWriter(mergeParser, mergeReporter,
				base + "kcov-merged/cobertura.xml");
		IWriter &mergeSonarqubeWriter = createSonarqubeWriter(mergeParser, mergeReporter,
				base + "kcov-merged/sonarqube.xml");
		(void)mkdir(fmt("%s/kcov-merged", base.c_str()).c_str(), 0755);

		reporter.registerListener(mergeParser);

		output.registerWriter(mergeParser);

		// Multiple binaries? Register the merged mode stuff
		if (countMetadata() > 0) {
			output.registerWriter(mergeHtmlWriter);
			output.registerWriter(mergeJsonWriter);
			output.registerWriter(mergeCoberturaWriter);
			output.registerWriter(mergeSonarqubeWriter);
			output.registerWriter(createCoverallsWriter(mergeParser, mergeReporter));
		} else {
			output.registerWriter(createCoverallsWriter(*parser, reporter));
		}

		output.registerWriter(htmlWriter);
		output.registerWriter(jsonWriter);
		output.registerWriter(coberturaWriter);
		output.registerWriter(sonarqubeWriter);
	}

	g_engine = engine;
	g_output = &output;
	g_reporter = &reporter;
	g_collector = &collector;
	g_solibHandler = &solibHandler;
	g_filter = &filter;
	g_basicFilter = &basicFilter;
	signal(SIGINT, ctrlc);
	signal(SIGTERM, ctrlc);

	if (conf.keyAsInt("daemonize-on-first-process-exit"))
		daemonize();

	parser->setupParser(&filter);
	output.start();
	solibHandler.startup();

	int ret = 0;

	if (runningMode != IConfiguration::MODE_REPORT_ONLY) {
		ret = collector.run(file);
	} else {
		parser->parse();
	}

	do_cleanup();

	return ret;
}

static int runSystemModeRecordFile(const std::string &dir, const std::string &file)
{
	pid_t child = fork();
	if (child < 0)
	{
		panic("Fork failed?\n");
	}
	else if (child == 0)
	{
		IConfiguration &conf = IConfiguration::getInstance();
		std::string rootDir = conf.keyAsString("binary-path") + conf.keyAsString("binary-name");

		if (dir.size() < rootDir.size())
		{
			error("kcov: Something strange with the directories: %s vs %s\n",
					dir.c_str(), rootDir.c_str());
			return -1;
		}

		// FIXME! There are stupid assumptions here...
		std::string dstDir = conf.keyAsString("out-directory") + "/" + dir.substr(rootDir.size());
		std::string dstFile = conf.keyAsString("out-directory") + "/" + file.substr(rootDir.size());

		conf.setKey("system-mode-write-file", dstFile);
		conf.setKey("binary-name", file);
		conf.setKey("binary-path", ""); // file uses an absolute path

		(void)mkdir(conf.keyAsString("out-directory").c_str(), 0755);
		(void)mkdir(dstDir.c_str(), 0755);

		runKcov(IConfiguration::MODE_COLLECT_ONLY);
	}
	else
	{
		// Parent
		int status;

		::waitpid(child, &status, 0);
	}

	return 0;
}

static int runSystemModeRecordDirectory(const std::string &base)
{
	DIR *dir = ::opendir(base.c_str());
	if (!dir)
	{
		error("Can't open directory %s\n", base.c_str());
		return -1;
	}

	// Loop through the directory structure
	struct dirent *de;
	for (de = ::readdir(dir); de; de = ::readdir(dir)) {
		std::string cur = base + "/" + de->d_name;

		if (strcmp(de->d_name, ".") == 0)
			continue;

		if (strcmp(de->d_name, "..") == 0)
			continue;

		struct stat st;

		if (lstat(cur.c_str(), &st) < 0)
			continue;

		// Executable file?
		if (S_ISREG(st.st_mode) &&
				(st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
		{
			runSystemModeRecordFile(base, cur);
			continue;
		}

		if (S_ISDIR(st.st_mode))
			runSystemModeRecordDirectory(cur);
	}
	::closedir(dir);

	return 0;
}

static int runSystemModeRecord()
{
	IConfiguration &conf = IConfiguration::getInstance();

	std::string base = conf.keyAsString("binary-path") + conf.keyAsString("binary-name");

	return runSystemModeRecordDirectory(base);
}

int main(int argc, const char *argv[])
{
	IConfiguration &conf = IConfiguration::getInstance();

	if (!conf.parse(argc, argv))
		return 1;

	IConfiguration::RunMode_t runningMode = (IConfiguration::RunMode_t)conf.keyAsInt("running-mode");

	if (runningMode == IConfiguration::MODE_MERGE_ONLY)
		return runMergeMode();

	if (runningMode == IConfiguration::MODE_SYSTEM_RECORD)
		return runSystemModeRecord();

	return runKcov(runningMode);
}
