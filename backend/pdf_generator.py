"""
Forensic PDF Report Generator
Phase 3: Professional forensic reports with ReportLab
"""

from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, red, orange, yellow, green
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from typing import Dict, Any, Optional, List
import hashlib


class ForensicReportGenerator:
    """Generate professional forensic analysis reports in PDF format"""
    
    def __init__(self, case_data: Dict[str, Any]):
        self.case_data = case_data
        self.timestamp = datetime.now()
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Create custom paragraph styles for forensic reports"""
        self.styles.add(ParagraphStyle(
            name='CaseTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='CaseHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=HexColor('#333333'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold',
            borderColor=HexColor('#e0e0e0'),
            borderWidth=1,
            borderPadding=10,
            borderRadius=4
        ))
        
        self.styles.add(ParagraphStyle(
            name='CaseMetadata',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=HexColor('#666666'),
            alignment=TA_CENTER,
            spaceAfter=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='ThreatCritical',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=red,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='ThreatHigh',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=orange,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Courier',
            leftIndent=20,
            textColor=HexColor('#2c3e50'),
            backColor=HexColor('#ecf0f1'),
            borderColor=HexColor('#bdc3c7'),
            borderWidth=1,
            borderPadding=10
        ))
    
    def generate(self) -> BytesIO:
        """Generate PDF report and return BytesIO object"""
        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.75*inch
        )
        
        # Build story (content elements)
        story = []
        
        # Title
        story.append(Paragraph(
            "Memory Forensics Analysis Report",
            self.styles['CaseTitle']
        ))
        
        # Metadata
        case_id = self.case_data.get('case_id', 'Unknown')[:12]
        metadata_text = f"""
        <b>Case ID:</b> {case_id} | 
        <b>Analyzed:</b> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} |
        <b>Status:</b> {self.case_data.get('status', 'Unknown').upper()}
        """
        story.append(Paragraph(metadata_text, self.styles['CaseMetadata']))
        story.append(Spacer(1, 0.3*inch))
        
        # Case Information Section
        story.append(Paragraph("1. Case Information", self.styles['CaseHeader']))
        
        case_info = [
            ['Parameter', 'Value'],
            ['Filename', self.case_data.get('filename', 'Unknown')],
            ['Uploaded At', self.case_data.get('uploaded_at', 'Unknown')],
            ['File Hash (SHA-256)', self._truncate_hash(self.case_data.get('sha256', 'Unknown'))],
            ['Analysis Status', self.case_data.get('status', 'Unknown')],
        ]
        
        case_table = Table(case_info, colWidths=[2*inch, 4.5*inch])
        case_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#bdc3c7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#ffffff'), HexColor('#ecf0f1')])
        ]))
        story.append(case_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Threats Section
        story.append(Paragraph("2. Threat Findings", self.styles['CaseHeader']))
        
        threat_cards = self.case_data.get('threat_cards', [])
        if threat_cards:
            for idx, threat in enumerate(threat_cards, 1):
                severity = threat.get('severity', 'Unknown').upper()
                title = threat.get('title', 'Unknown Finding')
                detail = threat.get('detail', 'No details')
                score = threat.get('score', 'N/A')
                
                # Color-code by severity
                if severity == 'CRITICAL':
                    style = self.styles['ThreatCritical']
                elif severity == 'HIGH':
                    style = self.styles['ThreatHigh']
                else:
                    style = self.styles['Normal']
                
                threat_text = f"""
                <b>{idx}. {title}</b><br/>
                <b>Severity:</b> <span color="{self._severity_color(severity)}">{severity}</span> | 
                <b>Risk Score:</b> {score}
                <br/>{detail}
                """
                story.append(Paragraph(threat_text, self.styles['Normal']))
                story.append(Spacer(1, 0.15*inch))
        else:
            story.append(Paragraph("No significant threats detected.", self.styles['Normal']))
        
        story.append(Spacer(1, 0.2*inch))
        
        # IOCs Section
        story.append(Paragraph("3. Indicators of Compromise (IOCs)", self.styles['CaseHeader']))
        
        iocs = self.case_data.get('iocs', {})
        
        # File Hashes
        if iocs.get('hashes'):
            story.append(Paragraph("<b>File Hashes</b>", self.styles['Heading3']))
            hash_items = '\n'.join([f"• {h}" for h in iocs['hashes']])
            story.append(Paragraph(hash_items, self.styles['CodeBlock']))
            story.append(Spacer(1, 0.15*inch))
        
        # IP Addresses
        if iocs.get('ips'):
            story.append(Paragraph("<b>IP Addresses</b>", self.styles['Heading3']))
            ip_items = '\n'.join([f"• {ip}" for ip in iocs['ips']])
            story.append(Paragraph(ip_items, self.styles['CodeBlock']))
            story.append(Spacer(1, 0.15*inch))
        
        # Suspicious DLLs
        if iocs.get('dlls'):
            story.append(Paragraph("<b>Suspicious DLLs</b>", self.styles['Heading3']))
            dll_items = '\n'.join([f"• {dll}" for dll in iocs['dlls']])
            story.append(Paragraph(dll_items, self.styles['CodeBlock']))
            story.append(Spacer(1, 0.15*inch))
        
        if not any([iocs.get('hashes'), iocs.get('ips'), iocs.get('dlls')]):
            story.append(Paragraph("No indicators of compromise detected.", self.styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Timeline Section
        timeline = self.case_data.get('timeline', [])
        if timeline:
            story.append(Paragraph("4. Threat Timeline", self.styles['CaseHeader']))
            
            for event in timeline[:10]:  # Limit to first 10 events
                timestamp = event.get('timestamp', 'Unknown')
                description = event.get('description', 'Unknown event')
                risk_score = event.get('risk_score', 0)
                
                timeline_text = f"""
                <b>{timestamp}</b> - {description}<br/>
                <i>Risk Score: {risk_score}</i>
                """
                story.append(Paragraph(timeline_text, self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
            
            if len(timeline) > 10:
                story.append(Paragraph(f"... and {len(timeline) - 10} more events", self.styles['Normal']))
            
            story.append(Spacer(1, 0.3*inch))
        
        # Footer
        story.append(Spacer(1, 0.2*inch))
        footer_text = f"""
        <font size="9" color="#999999">
        <b>Confidential:</b> This report contains sensitive forensic analysis information.<br/>
        Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')} | Case: {case_id}
        </font>
        """
        story.append(Paragraph(footer_text, self.styles['Normal']))
        
        # Build PDF
        doc.build(story)
        pdf_buffer.seek(0)
        return pdf_buffer
    
    @staticmethod
    def _truncate_hash(hash_value: str, length: int = 32) -> str:
        """Truncate hash for display"""
        if len(hash_value) > length:
            return hash_value[:length] + "..."
        return hash_value
    
    @staticmethod
    def _severity_color(severity: str) -> str:
        """Get color for severity level"""
        severity = severity.upper()
        if severity == 'CRITICAL':
            return '#d32f2f'
        elif severity == 'HIGH':
            return '#f57c00'
        elif severity == 'MEDIUM':
            return '#fbc02d'
        else:
            return '#388e3c'


def generate_forensic_pdf(case_data: Dict[str, Any]) -> BytesIO:
    """
    Convenience function to generate forensic PDF
    
    Args:
        case_data: Case information dict with 'threat_cards', 'iocs', 'timeline', etc.
    
    Returns:
        BytesIO object containing PDF data
    """
    generator = ForensicReportGenerator(case_data)
    return generator.generate()
