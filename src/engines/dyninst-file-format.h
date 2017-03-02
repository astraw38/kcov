#pragma once

struct dyninst_file
{
	uint32_t magic;
	uint32_t version;
	uint32_t n_entries;
	uint32_t data[];
};

const uint32_t DYNINST_MAGIC = 0x4d455247; // "MERG"
const uint32_t DYNINST_VERSION = 1;
