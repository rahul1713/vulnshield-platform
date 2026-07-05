'use client';

import { Button } from '@mui/material';
import { PlayArrow } from '@mui/icons-material';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { webScannerApi } from '@/lib/api';
import { MOCK_WEB_FINDINGS, paginate } from '@/lib/mock-data';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { SeverityChip } from '@/components/ui/SeverityChip';
import { WebScanFinding } from '@/types';

const columns: Column<WebScanFinding>[] = [
  { id: 'title', label: 'Finding', sortable: true },
  { id: 'url', label: 'URL' },
  { id: 'vulnerability_type', label: 'Type' },
  { id: 'owasp_category', label: 'OWASP', getValue: (row) => row.owasp_category || '—' },
  { id: 'severity', label: 'Severity', render: (row) => <SeverityChip severity={row.severity} /> },
  { id: 'created_at', label: 'Found', getValue: (row) => new Date(row.created_at).toLocaleDateString() },
];

export default function WebScannerPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);

  const { data, isLoading } = useQuery({
    queryKey: ['web-scanner', page, pageSize],
    queryFn: async () => {
      try {
        return await webScannerApi.listFindings({ page: page + 1, page_size: pageSize });
      } catch {
        return paginate(MOCK_WEB_FINDINGS, page + 1, pageSize);
      }
    },
  });

  return (
    <>
      <PageHeader
        title="Web Scanner"
        subtitle="Dynamic application security testing (DAST) findings"
        action={<Button variant="contained" startIcon={<PlayArrow />}>Start Web Scan</Button>}
      />
      <DataTable
        columns={columns}
        data={data?.items ?? []}
        total={data?.total ?? 0}
        loading={isLoading}
        page={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        searchPlaceholder="Search web findings..."
        getRowId={(row) => row.id}
      />
    </>
  );
}
