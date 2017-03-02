#include <file-parser.hh>
#include <engine.hh>
#include <configuration.hh>
#include <output-handler.hh>
#include <utils.hh>
#include <generated-data-base.hh>

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <signal.h>

#include <list>
#include <unordered_map>
#include <vector>
#include <utility>


#include <dyninst/BPatch.h>
#include <dyninst/BPatch_statement.h>
#include <dyninst/BPatch_point.h>
#include <dyninst/BPatch_function.h>

#include "dyninst-file-format.h"

using namespace kcov;

extern GeneratedData __dyninst_binary_library_data;

class DyninstEngine : public IEngine, public IFileParser
{
public:
	DyninstEngine() :
		m_mode(mode_unset),
		m_listener(NULL),
		m_bpatch(NULL),
		m_process(NULL),
		m_addressSpace(NULL),
		m_binaryEdit(NULL),
		m_image(NULL),
		m_reporterInitFunction(NULL),
		m_addressReporterFunction(NULL),
		m_breakpointIdx(0),
		m_checksum(0)
	{
		IParserManager::getInstance().registerParser(*this);
	}

	virtual ~DyninstEngine()
	{
	}

	// From IEngine
	virtual int registerBreakpoint(unsigned long addr)
	{
		if (m_mode == mode_write_file)
		{
			m_pendingAddresses.push_back(std::pair<uint64_t, uint32_t>(addr, m_breakpointIdx));
		}

		// Only needed for read mode, but always set it
		m_indexToAddress.push_back(addr);
		m_breakpointIdx++;

		return m_breakpointIdx - 1;
	}

	// From IFileParser
	virtual bool addFile(const std::string &filename, struct phdr_data_entry *phdr_data)
	{
		m_filename = filename;

		m_mode = mode_read_file;
		if (IConfiguration::getInstance().keyAsInt("system-mode-write-file"))
			m_mode = mode_write_file;

		for (FileListenerList_t::const_iterator it = m_fileListeners.begin();
				it != m_fileListeners.end();
				++it)
			(*it)->onFile(File(m_filename, IFileParser::FLG_NONE));


		// Actual parsing is done in start
		return true;
	}

	virtual bool setMainFileRelocation(unsigned long relocation)
	{
		return true;
	}

	virtual void registerLineListener(ILineListener &listener)
	{
		m_lineListeners.push_back(&listener);
	}

	virtual void registerFileListener(IFileListener &listener)
	{
		m_fileListeners.push_back(&listener);
	}

	virtual bool parse()
	{
		BPatch_Vector<BPatch_module *> *modules = m_image->getModules();

		if (modules)
			handleModules(*modules);

		// Handled when the program is launched
		return true;
	}

	virtual uint64_t getChecksum()
	{
		return m_checksum;
	}

	virtual enum IFileParser::PossibleHits maxPossibleHits()
	{
		return IFileParser::HITS_LIMITED;
	}

	virtual void setupParser(IFilter *filter)
	{
		if (!m_bpatch)
			m_bpatch = new BPatch();
	}

	std::string getParserType()
	{
		return "dyninst";
	}

	unsigned int matchParser(const std::string &filename, uint8_t *data, size_t dataSize)
	{
		IConfiguration &conf = IConfiguration::getInstance();

		if (conf.keyAsInt("system-mode-write-file") ||
				conf.keyAsInt("system-mode-read-results-file"))
			return match_perfect;

		return match_none;
	}

	bool start(IEventListener &listener, const std::string &executable)
	{
		m_listener = &listener;

		size_t sz;
		uint8_t *p = (uint8_t *)read_file(&sz, "%s", executable.c_str());
		m_checksum = hash_block(p, sz);
		free(p);

		m_binaryEdit = m_bpatch->openBinary(executable.c_str());

		if (!m_binaryEdit) {
			error("Can't open binary for rewriting\n");

			return false;
		}


		m_addressSpace = m_binaryEdit;
		m_image = m_addressSpace->getImage();

		if (!m_image) {
			// FIXME!

			return false;
		}

		return true;
	}


	bool continueExecution()
	{
		// After parsing, write the binary
		if (m_mode == mode_write_file)
		{
			handleFileWriter();

			for (unsigned i = 0; i < m_pendingAddresses.size(); i++)
			{
				std::pair<uint64_t, uint32_t> cur = m_pendingAddresses[i];
				registerPendingBreakpoint(cur.first, cur.second);
			}

			BPatch_function *main = lookupFunction("main");
			if (!main)
				return false;

			std::vector< BPatch_snippet * > args;
			BPatch_snippet id = BPatch_constExpr(m_checksum);
			BPatch_snippet size = BPatch_constExpr(m_breakpointIdx);

			args.push_back(&id);
			args.push_back(&size);
			BPatch_funcCallExpr call(*m_reporterInitFunction, args);

			BPatch_Vector<BPatch_point *> mainEntries;
			main->getEntryPoints(mainEntries);

			BPatchSnippetHandle *handle = m_addressSpace->insertSnippet(call, mainEntries,
					BPatch_firstSnippet);
			if (!handle) {
				error("Can't insert init func\n");
				return false;
			}

			m_binaryEdit->writeFile("/tmp/anka");
		}
		else
		{
			handleFileReader();
		}

		// Nothing to do after this
		reportEvent(ev_exit, 0, 0);

		return false;
	}


	void kill(int signal)
	{
	}

private:

	virtual void registerPendingBreakpoint(uint64_t addr, uint32_t idx)
	{
		std::vector<BPatch_point *> pts;

		if (!m_image->findPoints(addr, pts))
			return;

		std::vector< BPatch_snippet * > args;
		BPatch_snippet id = BPatch_constExpr(idx);

		args.push_back(&id);

		BPatch_funcCallExpr call(*m_addressReporterFunction, args);
			addSnippet(call, pts);
	}

	void addSnippet(BPatch_snippet &snippet, std::vector<BPatch_point *> &where)
	{
		BPatchSnippetHandle *handle = m_addressSpace->insertSnippet(snippet, where,
				BPatch_lastSnippet);

		if (!handle)
			return;

		for (std::vector<BPatch_point *>::iterator it = where.begin();
				it != where.end();
				++it)
			m_snippetsByPoint[*it] = handle;
	}


	bool handleFileReader()
	{
		std::string filename = fmt("/tmp/kcov-data/%08lx",(long) m_checksum);

		if (!file_exists(filename))
			return false;

		size_t sz;
		dyninst_file *p = (dyninst_file *)read_file(&sz, "%s", filename.c_str());

		if (p->magic != DYNINST_MAGIC)
		{
			error("Magic mismatch\n");
			return false;
		}

		if (p->version != DYNINST_VERSION)
		{
			error("version mismatch\n");
			return false;
		}

		if (p->n_entries > m_indexToAddress.size())
		{
			error("Too many entries in the file, %u vs %zu\n",
					p->n_entries, m_indexToAddress.size());
			free(p);

			return false;
		}

		for (unsigned i = 0; i < p->n_entries / 32; i++)
		{
			uint32_t cur = p->data[i];

			for (unsigned bit = 0; bit < 32; bit++)
			{
				if ( (cur & (1 << bit)) == 0)
					continue;

				reportEvent(ev_breakpoint, 0, m_indexToAddress[i * 32 + bit]);
			}
		}

		free(p);

		return true;
	}

	bool handleFileWriter()
	{
		std::string binaryLibraryPath =
				IOutputHandler::getInstance().getBaseDirectory() + "libkcov-binary-dyninst.so";

		write_file(__dyninst_binary_library_data.data(), __dyninst_binary_library_data.size(),
				"%s", binaryLibraryPath.c_str());

		BPatch_object *lib = m_binaryEdit->loadLibrary(binaryLibraryPath.c_str());
		if (!lib) {
			kcov_debug(INFO_MSG, "Can't load kcov dyninst library\n");

			return false;
		}

		m_addressReporterFunction = lookupFunction("kcov_dyninst_binary_report_address");
		m_reporterInitFunction = lookupFunction("kcov_dyninst_binary_init");

		if (!m_addressReporterFunction || !m_reporterInitFunction)
			return false;

		return true;
	}

	BPatch_function *lookupFunction(const char *name)
	{
		std::vector<BPatch_function *> funcs;

		m_image->findFunction(name, funcs);
		if (funcs.empty()) {
			error("unable to find function %s\n", name);

			return NULL;
		}

		return funcs[0];
	}

	uint64_t *readCoverageDatum(void *buf, size_t totalSize)
	{
		return (uint64_t *)buf;
	}

	void handleModules(BPatch_Vector<BPatch_module *> &modules)
	{
		for (BPatch_Vector<BPatch_module *>::iterator it = modules.begin();
				it != modules.end();
				++it)
		{
			BPatch_Vector<BPatch_statement> stmts;

			bool res = (*it)->getStatements(stmts);
			if (!res)
				continue;

			handleStatements(stmts);
		}
	}

	void handleStatements(BPatch_Vector<BPatch_statement> &stmts)
	{
		for (BPatch_Vector<BPatch_statement>::iterator it = stmts.begin();
				it != stmts.end();
				++it) {
			handleOneStatement(*it);
		}
	}

	void handleOneStatement(BPatch_statement &stmt)
	{
		const std::string filename = stmt.fileName();
		int lineNo = stmt.lineNumber();
		uint64_t addr = (uint64_t)stmt.startAddr();

		for (LineListenerList_t::iterator it = m_lineListeners.begin();
				it != m_lineListeners.end();
				++it)
			(*it)->onLine(filename, lineNo, addr);
	}

	void reportEvent(enum event_type type, int data = -1, uint64_t address = 0)
	{
		if (!m_listener)
			return;

		m_listener->onEvent(Event(type, data, address));
	}


	typedef std::vector<ILineListener *> LineListenerList_t;
	typedef std::vector<IFileListener *> FileListenerList_t;

	enum mode
	{
		mode_unset,
		mode_write_file,
		mode_read_file,
	};

	enum mode m_mode;
	std::string m_filename;

	LineListenerList_t m_lineListeners;
	FileListenerList_t m_fileListeners;

	IEventListener *m_listener;
	BPatch *m_bpatch;
	BPatch_process *m_process;
	BPatch_addressSpace *m_addressSpace;
	BPatch_binaryEdit *m_binaryEdit;
	BPatch_image *m_image;

	std::unordered_map<BPatch_point *, BPatchSnippetHandle *> m_snippetsByPoint;
	BPatch_function *m_reporterInitFunction;
	BPatch_function *m_addressReporterFunction;

	uint32_t m_breakpointIdx;
	uint32_t m_checksum;

	std::vector<uint64_t> m_indexToAddress;
	std::vector<std::pair<uint64_t, uint32_t>> m_pendingAddresses;
};



// This ugly stuff was inherited from bashEngine
static DyninstEngine *g_dyninstEngine;
class DyninstCtor
{
public:
	DyninstCtor()
	{
		g_dyninstEngine = new DyninstEngine();
	}
};
static DyninstCtor g_dyninstCtor;


class DyninstEngineCreator : public IEngineFactory::IEngineCreator
{
public:
	virtual ~DyninstEngineCreator()
	{
	}

	virtual IEngine *create(IFileParser &parser)
	{
		return g_dyninstEngine;
	}

	unsigned int matchFile(const std::string &filename, uint8_t *data, size_t dataSize)
	{
		// Better than the ptrace engine
		return 2;
	}
};

static DyninstEngineCreator g_dyninstEngineCreator;
