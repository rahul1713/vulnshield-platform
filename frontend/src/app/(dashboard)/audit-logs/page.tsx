'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { auditApi } from '@/lib/api';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { ProtectedRoute } from '@/components/layout/ProtectedRoute';
import { AuditLog } from '@/types';

const columns: Column<AuditLog>[] = [
  { id: 'created_at', label: 'Timestamp', sortable: true, getValue: (row) => new Date(row.created_at).toLocaleString() },
  { id: 'user_email', label: 'User', getValue: (row) => row.user_email || 'System' },
  { id: 'action', label: 'Action', sortable: true },
  { id: 'resource_type', label: 'Resource', getValue: (row) => row.resource_type || '—' },
  { id: 'resource_id', label: 'Resource ID', getValue: (row) => row.resource_id?.slice(0, 8) || '—' },
  { id: 'ip_address', label: 'IP Address', getValue: (row) => row.ip_address || '—' },
];

function AuditLogsContent() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);

  const { data, isLoading } = useQuery({
    queryKey: ['audit-logs', page, pageSize],
    queryFn: () => auditApi.list({ page: page + 1, page_size: pageSize }),
  });

  return (
    <>
      <PageHeader title="Audit Logs" subtitle="Security audit trail of platform actions" />
      <DataTable
        columns={columns}
        data={data?.items ?? []}
        total={data?.total ?? 0}
        loading={isLoading}
        page={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={setPageSize}
        searchPlaceholder="Search audit logs..."
        getRowId={(row) => row.id}
      />
    </>
  );
}

export default function AuditLogsPage() {
  return (
    <ProtectedRoute permissions={['audit:read']}>
      <AuditLogsContent />
    </ProtectedRoute>
  );
}
