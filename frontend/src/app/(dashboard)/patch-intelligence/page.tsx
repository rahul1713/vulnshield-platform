'use client';

import { Chip } from '@mui/material';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { patchApi } from '@/lib/api';
import { MOCK_PATCHES, paginate } from '@/lib/mock-data';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { SeverityChip } from '@/components/ui/SeverityChip';
import { PatchInfo } from '@/types';

const columns: Column<PatchInfo>[] = [
  { id: 'cve_identifier', label: 'CVE', sortable: true, getValue: (row) => row.cve_identifier || '—' },
  { id: 'patch_title', label: 'Patch Title', getValue: (row) => row.patch_title || '—' },
  {
    id: 'patch_available',
    label: 'Available',
    render: (row) => (
      <Chip label={row.patch_available ? 'Yes' : 'No'} size="small" color={row.patch_available ? 'success' : 'default'} />
    ),
  },
  { id: 'patch_severity', label: 'Severity', render: (row) => row.patch_severity ? <SeverityChip severity={row.patch_severity} /> : '—' },
  { id: 'patch_release_date', label: 'Release Date', getValue: (row) => row.patch_release_date || '—' },
  {
    id: 'eol_status',
    label: 'EOL',
    render: (row) => (
      <Chip label={row.eol_status ? 'EOL' : 'Supported'} size="small" color={row.eol_status ? 'error' : 'default'} variant="outlined" />
    ),
  },
];

export default function PatchIntelligencePage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);

  const { data, isLoading } = useQuery({
    queryKey: ['patch-intelligence', page, pageSize],
    queryFn: async () => {
      try {
        return await patchApi.list({ page: page + 1, page_size: pageSize });
      } catch {
        return paginate(MOCK_PATCHES, page + 1, pageSize);
      }
    },
  });

  return (
    <>
      <PageHeader title="Patch Intelligence" subtitle="Patch availability, vendor advisories, and remediation guidance" />
      <DataTable
        columns={columns}
        data={data?.items ?? []}
        total={data?.total ?? 0}
        loading={isLoading}
        page={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        searchPlaceholder="Search patches or CVEs..."
        getRowId={(row) => row.id}
      />
    </>
  );
}
