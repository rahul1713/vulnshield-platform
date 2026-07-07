'use client';

import { Button, CircularProgress } from '@mui/material';
import { PictureAsPdf } from '@mui/icons-material';
import { useState } from 'react';
import { reportsApi } from '@/lib/api';
import { downloadPdfBlob, ExecutiveReportInput, generateExecutivePdf } from '@/lib/executive-pdf';
import { demoStore } from '@/lib/demo-store';
import { isDemoSession } from '@/lib/api-client-helpers';
import { useToast } from '@/components/ui/ToastProvider';

interface ReportDownloadButtonProps {
  label?: string;
  filename: string;
  demoReportKey?: string;
  demoInput?: ExecutiveReportInput;
  reportId?: string;
  entityType?: 'scan' | 'codereview' | 'redteam';
  entityId?: string;
  size?: 'small' | 'medium';
  variant?: 'text' | 'outlined' | 'contained';
  disabled?: boolean;
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
        let input = demoInput;
        if (demoReportKey) {
          input = demoStore.getReportInput(demoReportKey) ?? input;
        }
        if (!input) {
          showToast('Report not ready yet — wait for scan to complete', 'warning');
          return;
        }
        const blob = generateExecutivePdf(input);
        downloadPdfBlob(blob, filename);
        showToast('Executive PDF downloaded', 'success');
        return;
      }

      let id = reportId;
      if (!id && entityType && entityId) {
        const created = await reportsApi.generateFromEntity(entityType, entityId);
        id = created.id;
      }
      if (!id) {
        showToast('No report available', 'error');
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
