'use client';

import { Button, CircularProgress } from '@mui/material';
import { PictureAsPdf } from '@mui/icons-material';
import { useState } from 'react';
import { reportsApi } from '@/lib/api';
import { downloadPdfBlob, ExecutiveReportInput, generateExecutivePdf } from '@/lib/executive-pdf';
import { isDemoSession } from '@/lib/api-client-helpers';
import { waitForDemoReportInput } from '@/lib/demo-helpers';
import { useToast } from '@/components/ui/ToastProvider';

interface ReportDownloadButtonProps {
  label?: string;
  filename: string;
  demoReportKey?: string;
  demoInput?: ExecutiveReportInput;
  reportId?: string;
  entityType?: 'scan' | 'codereview' | 'redteam' | 'webscan';
  entityId?: string;
  size?: 'small' | 'medium';
  variant?: 'text' | 'outlined' | 'contained';
  disabled?: boolean;
}

async function resolveDemoInput(
  demoReportKey?: string,
  demoInput?: ExecutiveReportInput
): Promise<ExecutiveReportInput | null> {
  const { demoStore } = await import('@/lib/demo-store');
  if (demoInput) return demoInput;
  if (!demoReportKey) return null;
  let input = demoStore.getReportInput(demoReportKey);
  if (input) return input;
  const ready = await waitForDemoReportInput(demoReportKey);
  return ready ? demoStore.getReportInput(demoReportKey) ?? null : null;
}

export function ReportDownloadButton({
  label = 'Download PDF Report',
  filename,
  demoReportKey,
  demoInput,
  reportId,
  entityType,
  entityId,
  size = 'small',
  variant = 'outlined',
  disabled,
}: ReportDownloadButtonProps) {
  const [loading, setLoading] = useState(false);
  const { showToast } = useToast();

  const handleDownload = async () => {
    setLoading(true);
    try {
      if (isDemoSession()) {
        const input = await resolveDemoInput(demoReportKey, demoInput);
        if (!input) {
          showToast('Report not ready yet — wait for the assessment to complete', 'warning');
          return;
        }
        const blob = await generateExecutivePdf(input);
        downloadPdfBlob(blob, filename);
        showToast('Executive PDF downloaded', 'success');
        return;
      }

      let id = reportId;
      if (!id && entityType && entityId && entityType !== 'webscan') {
        const created = await reportsApi.generateFromEntity(entityType, entityId);
        id = created.id;
      }
      if (!id && entityType === 'webscan' && demoReportKey) {
        const input = await resolveDemoInput(demoReportKey, demoInput);
        if (input) {
          const blob = await generateExecutivePdf(input);
          downloadPdfBlob(blob, filename);
          showToast('Executive PDF downloaded', 'success');
          return;
        }
      }
      if (!id) {
        showToast('No report available for this assessment', 'error');
        return;
      }
      await reportsApi.download(id, filename);
      showToast('Executive PDF downloaded', 'success');
    } catch (e) {
      showToast(e instanceof Error ? e.message : 'Failed to download report', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Button
      size={size}
      variant={variant}
      startIcon={loading ? <CircularProgress size={16} /> : <PictureAsPdf />}
      onClick={handleDownload}
      disabled={disabled || loading}
    >
      {label}
    </Button>
  );
}
