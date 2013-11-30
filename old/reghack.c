/*
 * reghack - Utility to binary-patch the embedded mac80211 regulatory rules.
 *
 *   Copyright (C) 2012 Jo-Philipp Wich <xm@subsignal.org>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>

struct ieee80211_freq_range {
    uint32_t start_freq_khz;
    uint32_t end_freq_khz;
    uint32_t max_bandwidth_khz;
};

struct ieee80211_power_rule {
    uint32_t max_antenna_gain;
    uint32_t max_eirp;
};

struct ieee80211_reg_rule {
    struct ieee80211_freq_range freq_range;
    struct ieee80211_power_rule power_rule;
    uint32_t flags;
};

struct ieee80211_regdomain {
    uint32_t n_reg_rules;
    char alpha2[2];
    uint8_t dfs_region;
    struct ieee80211_reg_rule reg_rules[1];
};

#define MHZ_TO_KHZ(freq) ((freq) * 1000)
#define KHZ_TO_MHZ(freq) ((freq) / 1000)
#define DBI_TO_MBI(gain) ((gain) * 100)
#define MBI_TO_DBI(gain) ((gain) / 100)
#define DBM_TO_MBM(gain) ((gain) * 100)
#define MBM_TO_DBM(gain) ((gain) / 100)

#define REG_RULE(start, end, bw, gain, eirp, reg_flags) \
{                           \
    .freq_range.start_freq_khz = MHZ_TO_KHZ(start), \
    .freq_range.end_freq_khz = MHZ_TO_KHZ(end), \
    .freq_range.max_bandwidth_khz = MHZ_TO_KHZ(bw), \
    .power_rule.max_antenna_gain = DBI_TO_MBI(gain),\
    .power_rule.max_eirp = DBM_TO_MBM(eirp),    \
    .flags = reg_flags,             \
}


struct search_regdomain {
	const char *desc;
	struct ieee80211_regdomain reg;
};

static const struct search_regdomain search_regdomains[] = {
	/* cfg80211.ko matches */
	{
		.desc = "core world5 regdomain in cfg80211/reg.o",
		.reg  = {
			.alpha2 = "00",
			.reg_rules = {
				REG_RULE(2402, 2472, 40, 6, 20, 0)
			},
			.n_reg_rules = 5
		}
	}, {
		.desc = "core world6 regdomain in cfg80211/reg.o",
		.reg  = {
			.alpha2 = "00",
			.reg_rules = {
				REG_RULE(2402, 2472, 40, 6, 20, 0)
			},
			.n_reg_rules = 6
		}
	}, {
		.desc = "embedded 00 regdomain in cfg80211/regdb.o",
		.reg  = {
			.alpha2 = "00",
			.reg_rules = {
				REG_RULE(2402, 2472, 40, 3, 20, 0)
			},
			.n_reg_rules = 5
		}
	}, {
		.desc = "embedded US regdomain in cfg80211/regdb.o",
		.reg  = {
			.alpha2 = "US",
			.reg_rules = {
				REG_RULE(2402, 2472, 40, 3, 27, 0)
			},
			.n_reg_rules = 6
		}
	},

	/* ath.ko matches */
	{
		.desc = "ath world regdomain with 3 rules in ath/regd.o",
		.reg  = {
			.alpha2 = "99",
			.reg_rules = {
				REG_RULE(2402, 2472, 40, 0, 20, 0)
			},
			.n_reg_rules = 3
		}
	}, {
		.desc = "ath world regdomain with 4 rules in ath/regd.o",
		.reg  = {
			.alpha2 = "99",
			.reg_rules = {
				REG_RULE(2402, 2472, 40, 0, 20, 0)
			},
			.n_reg_rules = 4
		}
	}, {
		.desc = "ath world regdomain with 5 rules in ath/regd.o",
		.reg  = {
			.alpha2 = "99",
			.reg_rules = {
				REG_RULE(2402, 2472, 40, 0, 20, 0)
			},
			.n_reg_rules = 5
		}
	}
};


int main(int argc, char **argv)
{
	int i, j, fd;
	int found = 0;

	void *map;
	struct stat s;

	struct ieee80211_regdomain *r;
	struct ieee80211_reg_rule r2 = REG_RULE(2400, 2483, 40, 0, 30, 0);
	struct ieee80211_reg_rule r5 = REG_RULE(5140, 5860, 40, 0, 30, 0);

	if (argc < 2)
	{
		printf("Usage: %s module.ko\n", argv[0]);
		exit(1);
	}

	if (stat(argv[1], &s))
	{
		perror("stat()");
		exit(1);
	}

	if ((fd = open(argv[1], O_RDWR)) == -1)
	{
		perror("open()");
		exit(1);
	}

	map = mmap(NULL, s.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	if (map == MAP_FAILED)
	{
		perror("mmap()");
		exit(1);
	}

	for (i = 0; i < (s.st_size - sizeof(search_regdomains[0].reg)); i += sizeof(uint32_t))
	{
		for (j = 0; j < (sizeof(search_regdomains)/sizeof(search_regdomains[0])); j++)
		{
			if (!memcmp(map + i, &search_regdomains[j].reg, sizeof(search_regdomains[j].reg)))
			{
				printf("Patching @ 0x%08x: %s\n", i, search_regdomains[j].desc);

				r = map + i;
				r->reg_rules[0] = r2;
				r->reg_rules[1] = r5;
				r->n_reg_rules = 2;

				found = 1;
			}
		}
	}

	if (munmap(map, s.st_size))
	{
		perror("munmap()");
		exit(1);
	}

	close(fd);

	if (!found)
	{
		printf("Unable to find regulatory rules (already patched?)\n");
		exit(1);
	}

	return 0;
}
