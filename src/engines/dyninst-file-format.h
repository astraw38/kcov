#pragma once

struct dyninst_file
{
	uint32_t magic;
	uint32_t version;
	uint32_t n_entries;
	uint32_t header_checksum;
	uint32_t filename_offset;
	uint32_t kcov_options_offset; // --include-pattern etc
	uint32_t data[];
};

const uint32_t DYNINST_MAGIC = 0x4d455247; // "MERG"
const uint32_t DYNINST_VERSION = 1;
