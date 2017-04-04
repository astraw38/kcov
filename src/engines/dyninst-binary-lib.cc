#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <utils.hh>
#include <swap-endian.hh>

#include "dyninst-file-format.h"

struct Instance
{
	uint32_t *bits;
	size_t bitVectorSize;
	std::string options;
	std::string filename;
	uint32_t id;
	time_t last_time;

	bool initialized;
};

static Instance g_instance;
static uint32_t early_hits[4096];
static uint32_t early_hits_index;


static void write_report(unsigned int idx)
{
	(void)mkdir("/tmp/kcov-data", 0755);

	std::string out = fmt("/tmp/kcov-data/%08lx", (long)g_instance.id);
	std::string tmp = fmt("%s.%u", out.c_str(), idx);
	FILE *fp = fopen(tmp.c_str(), "w");

	// What to do?
	if (!fp)
	{
		fprintf(stderr, "kcov-binary-lib: Can't write outfile\n");
		return;
	}

	struct dyninst_file dst;

	dst.magic = DYNINST_MAGIC;
	dst.version = DYNINST_VERSION;
	dst.n_entries = g_instance.bitVectorSize;
	dst.filename_offset = dst.n_entries * sizeof(uint32_t) + sizeof(dst);
	dst.kcov_options_offset = dst.filename_offset + g_instance.filename.size() + 1;

	fwrite(&dst, sizeof(dst), 1, fp);
	fwrite(g_instance.bits, sizeof(uint32_t), g_instance.bitVectorSize, fp);
	fprintf(fp, "%s", g_instance.filename.c_str());
	fputc('\0', fp);
	fprintf(fp, "%s", g_instance.options.c_str());
	fputc('\0', fp);

	fclose(fp);
	rename(tmp.c_str(), out.c_str());
}

static void write_at_exit(void)
{
	write_report(0);
}

static void read_report(void)
{
	std::string in = fmt("/tmp/kcov-data/%08lx", (long)g_instance.id);

	if (!file_exists(in))
	{
		return;
	}

	size_t sz;
	struct dyninst_file *src = (struct dyninst_file *)read_file(&sz, "%s", in.c_str());
	if (!src)
	{
		printf("Can't read\n");
		return;
	}

	size_t expectedSize = g_instance.bitVectorSize * sizeof(uint32_t) + sizeof(struct dyninst_file) +
			g_instance.filename.size() + 1 +
			g_instance.options.size() + 1;

	// Wrong size
	if (sz != expectedSize)
	{
		printf("Wrong size??? %zu vs %zu\n", sz, g_instance.bitVectorSize * sizeof(uint32_t));
		return;
	}

	// Skip old versions
	if (src->magic != DYNINST_MAGIC ||
			src->version != DYNINST_VERSION)
	{
		printf("Wrong magic\n");
		return;
	}

	if (src->n_entries * sizeof(uint32_t) >= expectedSize)
	{
		printf("Too many entries\n");
		return;
	}

	memcpy(g_instance.bits, (void *)src->data, src->n_entries * sizeof(uint32_t));

	free(src);
}

extern "C" void kcov_dyninst_binary_init(uint32_t id, size_t vectorSize, const char *filename, const char *kcovOptions)
{
	g_instance.bits = (uint32_t *)calloc(vectorSize, sizeof(uint32_t));
	g_instance.bitVectorSize = vectorSize;
	g_instance.id = id;
	g_instance.filename = filename;
	g_instance.options = kcovOptions;
	g_instance.last_time = time(NULL);

	read_report();

	atexit(write_at_exit);
	g_instance.initialized = true;
}

extern "C" void kcov_dyninst_binary_report_address(uint32_t bitIdx)
{
	unsigned int wordIdx = bitIdx / 32;
	unsigned int offset = bitIdx % 32;

	// Handle hits which happen before we're initialized
	if (!g_instance.initialized)
	{
		uint32_t dst = __sync_fetch_and_add(&early_hits_index, 1);

		if (dst >= sizeof(early_hits) / sizeof(early_hits[0]))
		{
			fprintf(stderr, "kcov: Library not initialized yet and hit table full, missing point %u\n", bitIdx);
			return;
		}
		early_hits[dst] = bitIdx;
		return;
	}

	if (wordIdx >= g_instance.bitVectorSize)
	{
		fprintf(stderr, "kcov: INTERNAL ERROR: Index out of bounds (%u vs %zu)\n",
				wordIdx, g_instance.bitVectorSize);
		return;
	}

	if (early_hits_index != 0)
	{
		uint32_t to_loop = early_hits_index;

		early_hits_index = 0; // Avoid inifite recursion
		for (uint32_t i = 0; i < to_loop; i++)
		{
			kcov_dyninst_binary_report_address(early_hits[i]);
		}
	}

	// Update the bit atomically
	uint32_t *p = &g_instance.bits[wordIdx];

	// Already hit?
	if (*p & (1 << offset))
		return;

	uint32_t val, newVal;
	do
	{
		val = *p;
		newVal = val | (1 << offset);

	} while (!__sync_bool_compare_and_swap(p, val, newVal));


	// Write out the report
	time_t now = time(NULL);
	if (now - g_instance.last_time >= 2)
	{
		write_report(bitIdx);
		g_instance.last_time = now;
	}
}
