'use client';

import { useState } from 'react';
import { Alert } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { vulnerabilitiesApi } from '@/lib/api';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { SeverityChip, StatusChip } from '@/components/ui/SeverityChip';
import { VulnDetailDrawer } from '@/components/vulnerabilities/VulnDetailDrawer';
import { useToast } from '@/components/ui/ToastProvider';
import { Vulnerability, VulnStatus } from '@/types';

const columns: Column<Vulnerability>[] = [
  { id: 'title', label: 'Title', sortable: true },
  { id: 'cve_identifier', label: 'CVE', getValue: (row) => row.cve_identifier || '—' },
  { id: 'asset_name', label: 'Asset', getValue: (row) => row.asset_name || '—' },
  { id: 'severity', label: 'Severity', render: (row) => <SeverityChip severity={row.severity} /> },
  { id: 'cvss_score', label: 'CVSS', getValue: (row) => row.cvss_score?.toFixed(1) ?? '—' },
  { id: 'status', label: 'Status', render: (row) => <StatusChip status={row.status} /> },
  { id: 'risk_score', label: 'Risk', getValue: (row) => row.risk_score?.toFixed(1) ?? '—' },
];

export default function VulnerabilitiesPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Vulnerability | null>(null);
  const queryClient = useQueryClient();
  const { showToast } = useToast();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['vulnerabilities', page, pageSize, search],
    queryFn: () => vulnerabilitiesApi.list({ page: page + 1, page_size: pageSize, search }),
  });

  const statusMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: VulnStatus }) =>
      vulnerabilitiesApi.updateStatus(id, status),
    onSuccess: () => {
      showToast('Vulnerability status updated', 'success');
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
    },
  });

  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        subtitle="Click a row to view details and update status"
      />
      {isError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error instanceof Error ? error.message : 'Failed to load vulnerabilities'}
        </Alert>
      )}
      <DataTable
        columns={columns}
        data={data?.items ?? []}
        total={data?.total ?? 0}
        loading={isLoading}
        page={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={(size) => { setPageSize(size); setPage(0); }}
        onSearchChange={(q) => { setSearch(q); setPage(0); }}
        onRowClick={(row) => setSelected(row)}
        searchPlaceholder="Search vulnerabilities..."
        getRowId={(row) => row.id}
      />
      <VulnDetailDrawer
        vuln={selected}
        open={!!selected}
        onClose={() => setSelected(null)}
        onStatusChange={async (id, status) => {
          await statusMutation.mutateAsync({ id, status });
          setSelected((prev) => (prev ? { ...prev, status } : null));
        }}
      />
    </>
  );
}
