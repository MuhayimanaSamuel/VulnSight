import { jsPDF } from 'jspdf';
import { ScanResponse } from '../types/scanner';

export function exportSecurityReportToPdf(scan: ScanResponse): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let y = 18;

  // Header Banner Background
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(0, 0, pageWidth, 32, 'F');

  // Title
  doc.setTextColor(56, 189, 248); // sky-400
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.text('VulnSight // Security Assessment Report', 14, y);

  // Subtitle
  y += 7;
  doc.setTextColor(148, 163, 184); // slate-400
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.text('DevSecOps Vulnerability Scan, OSINT Recon & AI Threat Remediation', 14, y);

  // Status Badge on the right
  const badgeText = `OVERALL RISK: ${scan.overallRisk}`;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  if (scan.overallRisk === 'CRITICAL') {
    doc.setTextColor(239, 68, 68);
  } else if (scan.overallRisk === 'HIGH') {
    doc.setTextColor(249, 115, 22);
  } else if (scan.overallRisk === 'MEDIUM') {
    doc.setTextColor(234, 179, 8);
  } else {
    doc.setTextColor(34, 197, 94);
  }
  doc.text(badgeText, pageWidth - 14, 20, { align: 'right' });

  y = 42;

  // Metadata Panel
  doc.setFillColor(248, 250, 252); // slate-50
  doc.setDrawColor(226, 232, 240); // slate-200
  doc.roundedRect(14, y, pageWidth - 28, 30, 2, 2, 'FD');

  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);
  doc.setFont('helvetica', 'bold');

  // Left col
  doc.text('Target Host:', 18, y + 6);
  doc.setFont('helvetica', 'normal');
  doc.text(scan.target, 45, y + 6);

  doc.setFont('helvetica', 'bold');
  doc.text('Resolved IP:', 18, y + 12);
  doc.setFont('helvetica', 'normal');
  doc.text(scan.resolvedIp, 45, y + 12);

  doc.setFont('helvetica', 'bold');
  doc.text('Registrar / WHOIS:', 18, y + 18);
  doc.setFont('helvetica', 'normal');
  doc.text(scan.recon?.registrar || 'ICANN Accredited Registrar', 52, y + 18);

  doc.setFont('helvetica', 'bold');
  doc.text('Scan ID:', 18, y + 24);
  doc.setFont('helvetica', 'normal');
  doc.text(scan.scanId, 45, y + 24);

  // Right col
  doc.setFont('helvetica', 'bold');
  doc.text('Timestamp:', 110, y + 6);
  doc.setFont('helvetica', 'normal');
  doc.text(new Date(scan.timestamp).toUTCString(), 135, y + 6);

  doc.setFont('helvetica', 'bold');
  doc.text('AI Engine:', 110, y + 12);
  doc.setFont('helvetica', 'normal');
  doc.text(scan.aiAdvice?.engine || 'gemini-3.8-flash', 135, y + 12);

  doc.setFont('helvetica', 'bold');
  doc.text('Execution Duration:', 110, y + 18);
  doc.setFont('helvetica', 'normal');
  doc.text(`${scan.durationMs} ms`, 145, y + 18);

  doc.setFont('helvetica', 'bold');
  doc.text('Nameservers:', 110, y + 24);
  doc.setFont('helvetica', 'normal');
  doc.text((scan.recon?.nameservers || []).slice(0, 2).join(', ') || 'N/A', 135, y + 24);

  y += 37;

  // Executive KPI summary boxes
  const colWidth = (pageWidth - 28 - 9) / 4;
  const kpis = [
    { label: 'Ports Probed', value: scan.totalPortsScanned.toString(), color: [51, 65, 85] },
    { label: 'Open Ports', value: scan.openPortsCount.toString(), color: scan.openPortsCount > 0 ? [220, 38, 38] : [22, 163, 74] },
    { label: 'Max CVSS Score', value: scan.maxCvss > 0 ? scan.maxCvss.toFixed(1) : '0.0', color: scan.maxCvss >= 7 ? [220, 38, 38] : [51, 65, 85] },
    { label: 'Exposed Web Dirs', value: (scan.directories?.filter(d => d.accessible).length || 0).toString(), color: [217, 119, 6] }
  ];

  kpis.forEach((kpi, idx) => {
    const kpiX = 14 + idx * (colWidth + 3);
    doc.setFillColor(241, 245, 249);
    doc.setDrawColor(203, 213, 225);
    doc.roundedRect(kpiX, y, colWidth, 16, 1.5, 1.5, 'FD');

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text(kpi.label, kpiX + 4, y + 5);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(kpi.color[0], kpi.color[1], kpi.color[2]);
    doc.text(kpi.value, kpiX + 4, y + 12);
  });

  y += 24;

  // Ports & Findings Section
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('Audited Ports & Exposed Services', 14, y);

  y += 5;

  // Table Header
  doc.setFillColor(30, 41, 59);
  doc.rect(14, y, pageWidth - 28, 6.5, 'F');
  doc.setFontSize(7.5);
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.text('Port / Proto', 16, y + 4.5);
  doc.text('Service', 42, y + 4.5);
  doc.text('Status', 72, y + 4.5);
  doc.text('Risk', 95, y + 4.5);
  doc.text('Identified Vulnerabilities / CVEs', 125, y + 4.5);

  y += 6.5;

  // Table Rows
  scan.ports.forEach((port) => {
    const isEven = port.port % 2 === 0;
    doc.setFillColor(isEven ? 255 : 248, isEven ? 255 : 250, isEven ? 255 : 252);
    doc.rect(14, y, pageWidth - 28, 8, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(15, 23, 42);
    doc.text(`${port.port}/tcp`, 16, y + 5);

    doc.setFont('helvetica', 'normal');
    doc.text(port.service.toUpperCase(), 42, y + 5);

    if (port.status === 'OPEN') {
      doc.setTextColor(220, 38, 38);
      doc.setFont('helvetica', 'bold');
    } else {
      doc.setTextColor(100, 116, 139);
      doc.setFont('helvetica', 'normal');
    }
    doc.text(port.status, 72, y + 5);

    doc.setFont('helvetica', 'bold');
    if (port.riskLevel === 'CRITICAL') doc.setTextColor(220, 38, 38);
    else if (port.riskLevel === 'HIGH') doc.setTextColor(234, 88, 12);
    else if (port.riskLevel === 'MEDIUM') doc.setTextColor(202, 138, 4);
    else doc.setTextColor(22, 163, 74);
    doc.text(port.riskLevel, 95, y + 5);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    const cveStr = port.vulnerabilities.length > 0
      ? port.vulnerabilities.map(c => `${c.id} (${c.cvss})`).join(', ')
      : 'No critical CVEs';
    doc.text(doc.splitTextToSize(cveStr, 65)[0] || 'None', 125, y + 5);

    y += 8;
  });

  y += 6;

  // AI Defensive Hardening Checklist
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('Administrator Defensive Hardening Runbook (Gemini AI)', 14, y);
  y += 5;

  const checklist = scan.aiAdvice?.defensiveHardeningChecklist || [
    'Enforce default-deny ingress firewall rule on perimeter cloud security groups.',
    'Decommission unneeded legacy network listeners (ports 21, 23, 3306).',
    'Deny web access to dotfiles and configuration scripts (/.env, /.git).'
  ];

  checklist.slice(0, 4).forEach((item) => {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(22, 163, 74);
    doc.text('•', 16, y);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    const splitText = doc.splitTextToSize(item, pageWidth - 36);
    doc.text(splitText, 20, y);
    y += 4.5 * splitText.length;
  });

  // Footer
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  doc.text('CONFIDENTIAL SECURITY AUDIT · FOR AUTHORIZED EDUCATIONAL & PENETRATION TESTING PURPOSES ONLY', 14, 285);
  doc.text('VulnSight DevSecOps Platform · https://github.com/your-username/vulnsight', pageWidth - 14, 285, { align: 'right' });

  // Save PDF
  doc.save(`vulnsight-report-${scan.target.replace(/[^a-zA-Z0-9]/g, '_')}-${Date.now()}.pdf`);
}
