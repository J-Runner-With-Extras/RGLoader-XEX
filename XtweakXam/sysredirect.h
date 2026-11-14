#pragma once

#include "stdafx.h"

// Redirects opens of the HDD system extended/aux partitions (where the dashboard
// extensions and avatar packages live) to folders on the main HDD partition, so the real
// partitions can keep the set another boot needs. hddFolder is relative to Hdd:,
// e.g. "Filesystems\\sysext"; it must hold SystemExtPartition and SystemAuxPartition.
BOOL SysRedirect_Install(const char* hddFolder);
