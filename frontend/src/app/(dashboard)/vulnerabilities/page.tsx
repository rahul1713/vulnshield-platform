'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { vulnerabilitiesApi } from '@/lib/api';
import { MOCK_VULNERABILITIES, paginate } from '@/lib/mock-data';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { SeverityChip, StatusChip } from '@/components/ui/SeverityChip';
import { Vulnerability } from '@/types';

const columns: Column<Vulnerability>[] = [
  { id: 'title', label: 'Title', sortable: true },
  { id: 'cve_identifier', label: 'CVE', getValue: (row) => row.cve_identifier || '—' },
  { id: 'asset_name', label: 'Asset', getValue: (row) => row.asset_name || '—' },
  { id: 'severity', label: 'Severity', render: (row) => <SeverityChip severity={row.severity} /> },
  { id: 'cvss_score', label: 'CVSS', getValue: (row) => row.cvss_score?.toFixed(1) ?? '—' },
  { id: 'status', label: 'Status', render: (row) => <StatusChip status={row.status} /> },
  { id: 'risk_score', label: 'Risk', getValue: (row) => row.risk_score?.toFixed(1) ?? '—' },
  { id: 'first_detected', label: 'Detected', getValue: (row) => new Date(row.first_detected).toLocaleDateString() },
];

export default function VulnerabilitiesPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [search, setSearch] = useState('');

  const { data, isLoading } = useQuery({
    queryKey: ['vulnerabilities', page, pageSize, search],
    queryFn: async () => {
      try {
        return await vulnerabilitiesApi.list({ page: page + 1, page_size: pageSize, search });
      } catch {
        const filtered = search
          ? MOCK_VULNERABILITIES.filter((v) => v.title.toLowerCase().includes(search.toLowerCase()))
          : MOCK_VULNERABILITIES;
        return paginate(filtered, page + 1, pageSize);
      }
    },
  });

  return (
    <>
      <PageHeader title="Vulnerabilities" subtitle="Track and remediate security findings across your environment" />
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
        searchPlaceholder="Search vulnerabilities..."
        filters={[
          { id: 'severity', label: 'All Severities', options: [
            { value: 'critical', label: 'Critical' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low' },
          ]},
          { id: 'status', label: 'All Statuses', options: [
            { value: 'open', label: 'Open' },
            { value: 'in_progress', label: 'In Progress' },
            { value: 'resolved', label: 'Resolved' },
          ]},
        ]}
        getRowId={(row) => row.id}
      />
    </>
  );
}
