'use client';

/** Trigger a file download in the browser with reliable blob handling. */
export function downloadBlob(blob: Blob, filename: string): void {
  if (!blob || blob.size === 0) {
    throw new Error('Download failed: empty file');
  }

  const safeName = filename.endsWith('.pdf') ? filename : `${filename}.pdf`;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = safeName;
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();

  // Revoke after the browser has started the download (immediate revoke can cancel it).
  window.setTimeout(() => {
    anchor.remove();
    URL.revokeObjectURL(url);
  }, 2000);
}

export async function validatePdfBlob(blob: Blob): Promise<Blob> {
  const header = await blob.slice(0, 5).text();
  if (!header.startsWith('%PDF')) {
    throw new Error('Download failed: server did not return a valid PDF');
  }
  return blob;
}
