'use client';

import { Button } from '@mui/material';
import { Code } from '@mui/icons-material';
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { codeReviewApi } from '@/lib/api';
import { isDemoSession } from '@/lib/api-client-helpers';
import { waitForDemoReportInput } from '@/lib/demo-helpers';
import { PageHeader } from '@/components/ui/PageHeader';
import { DataTable, Column } from '@/components/ui/DataTable';
import { StatusChip } from '@/components/ui/SeverityChip';
import { CreateCodeReviewDialog, CodeReviewInput } from '@/components/code-review/CreateCodeReviewDialog';
import { ReportDownloadButton } from '@/components/reports/ReportDownloadButton';
import { useToast } from '@/components/ui/ToastProvider';
import { CodeReview } from '@/types';
import { Stack } from '@mui/material';

const columns: Column<CodeReview>[] = [
  { id: 'repository_url', label: 'Target', getValue: (row) => row.repository_url?.replace('https://github.com/', '') || '—' },
  { id: 'branch', label: 'Branch' },
  { id: 'language', label: 'Language', getValue: (row) => row.language || '—' },
  { id: 'status', label: 'Status', render: (row) => <StatusChip status={row.status} /> },
  { id: 'findings_count', label: 'Findings', sortable: true },
  { id: 'started_at', label: 'Started', getValue: (row) => row.started_at ? new Date(row.started_at).toLocaleString() : '—' },
  { id: 'completed_at', label: 'Completed', getValue: (row) => row.completed_at ? new Date(row.completed_at).toLocaleString() : '—' },
];

export default function CodeReviewPage() {
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [dialogOpen, setDialogOpen] = useState(false);
  const queryClient = useQueryClient();
  const { showToast } = useToast();

  const { data, isLoading } = useQuery({
    queryKey: ['code-review', page, pageSize],
    queryFn: () => codeReviewApi.list({ page: page + 1, page_size: pageSize }),
    refetchInterval: 3000,
  });

  const createMutation = useMutation({
    mutationFn: (input: CodeReviewInput) => {
      if (input.mode === 'repository') {
        return codeReviewApi.create({
          repository_url: input.repository_url,
          language: input.language,
          branch: input.branch,
        });
      }
      if (input.mode === 'path') {
        return codeReviewApi.create({ file_path: input.file_path, language: input.language });
      }
      return codeReviewApi.create({
        source_code: input.source_code,
        language: input.language,
        file_path: input.file_path,
      });
    },
    onSuccess: async (review) => {
      if (isDemoSession()) {
        await waitForDemoReportInput(`codereview:${review.id}`);
        showToast('SAST complete — executive PDF report ready', 'success');
      } else if (review.status === 'running') {
        showToast('SAST scan started — results appear when status is completed', 'success');
      } else if (review.status === 'completed') {
        showToast('SAST complete — executive PDF report ready', 'success');
      } else {
        showToast('Code review queued', 'info');
      }
      queryClient.invalidateQueries({ queryKey: ['code-review'] });
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
    onError: (e: Error) => showToast(e.message, 'error'),
  });

  return (
    <>
      <PageHeader
        title="AI Code Review"
        subtitle="SAST via repository, file path, or pasted code — executive PDF with remediation"
        action={
          <Button variant="contained" startIcon={<Code />} onClick={() => setDialogOpen(true)}>
            New Review
          </Button>
        }
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
        searchPlaceholder="Search reviews..."
        getRowId={(row) => row.id}
        rowActions={(row) => (
          <Stack direction="row" justifyContent="flex-end">
            {row.status === 'completed' && (
              <ReportDownloadButton
                filename={`sast-report-${row.id}.pdf`}
                demoReportKey={`codereview:${row.id}`}
                entityType="codereview"
                entityId={row.id}
                label="PDF"
              />
            )}
          </Stack>
        )}
      />
      <CreateCodeReviewDialog
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        onSubmit={async (input) => {
          await createMutation.mutateAsync(input);
        }}
      />
    </>
  );
}
