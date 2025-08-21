import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { report } from 'node:process';

@Component({
  selector: 'app-scan',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './scan.component.html',
  styleUrls: ['./scan.component.css']
})
export class ScanComponent {
  iocValue = '';
  aiSummary = '';
  type: string | null = null;
  target: string | null = null;

  ipData: any = null;
  urlData: any = null;
  domainData: any = null;
  hashData: any = null;

  loading = false;
  errorMessage = '';

  constructor(private http: HttpClient) {}

  scanIOC() {
    if (!this.iocValue.trim()) return;

    this.loading = true;
    this.errorMessage = '';
    this.aiSummary = '';
    this.type = null;
    this.target = null;
    this.ipData = null;
    this.urlData = null;
    this.domainData = null;
    this.hashData = null;

    this.http.post<any>('http://localhost:3000/scan', { target: this.iocValue })
      .subscribe({
        next: (response) => {
          this.type = response.type;
          this.target = response.target;

          // AI summary
          this.aiSummary = response.analysis?.gemini?.brief || '';

          // IP
          if (this.type === 'ip') {
            const vtStats = response.analysis?.virustotal?.last_analysis_stats || null;
            const enginesObj = response.analysis?.virustotal?.malicious_engines || [];

            this.ipData = {
              virustotal: {
                vt_link: response.analysis?.virustotal?.vt_link || '',
                last_analysis_stats: vtStats,
                malicious_engines: enginesObj
                  .filter((e: any) => e.category === 'malicious' || e.category === 'suspicious')
                  .map((e: any) => ({
                    engine: e.engine || '',
                    result: e.category || ''
                  }))
              },
              abuseipdb: response.analysis?.abuseipdb || {}
            };
          }

          // URL
          else if (this.type === 'url') {
            const vtStats = response.analysis?.virustotal?.last_analysis_stats || null;
            const enginesObj = response.analysis?.virustotal?.malicious_engines || [];
            this.urlData = {
              virustotal: {
                vt_link: response.analysis?.virustotal?.vt_link || '',
                last_analysis_stats: vtStats,
                malicious_engines: enginesObj
                  .filter((e: any) => e.category === 'malicious' || e.category === 'suspicious')
                  .map((e: any) => ({
                    engine: e.engine || '',
                    result: e.category || ''
                  }))
              },
              urlScan: {
                screenshot: response.analysis?.urlscan?.scan_metadata?.screenshot || '',
                report_link: response.analysis?.urlscan?.scan_metadata?.report_link || '',
                security_verdicts: response.analysis?.urlscan?.security_verdicts || {},
                network_activity: response.analysis?.urlscan?.network_activity || {},
              }
            };
          }

          // Domain
          else if (this.type === 'domain') {
            const vtStats = response.analysis?.virustotal?.last_analysis_stats || null;
            const enginesObj = response.analysis?.virustotal?.malicious_engines || [];

            this.domainData = {
              virustotal: {
                vt_link: response.analysis?.virustotal?.vt_link || '',
                last_analysis_stats: vtStats,
                malicious_engines: enginesObj
                  .filter((e: any) => e.category === 'malicious' || e.category === 'suspicious')
                  .map((e: any) => ({
                    engine: e.engine || '',
                    result: e.category || ''
                  }))
              },
              whois: {
                registrar: response.analysis?.whois?.registrar || '',
                creation_date: response.analysis?.whois?.created || '',
                expiration_date: response.analysis?.whois?.expires || '',
                name_servers: response.analysis?.whois?.nameservers || [],
                status: response.analysis?.whois?.status || '',
                country: response.analysis?.whois?.country || '',
                dns: {
                  ipV4: response.analysis?.whois?.dns?.a || [],
                  ipV6: response.analysis?.whois?.dns?.aaaa || [],
                },
              }
            };
          }

          // Hash
          else if (this.type === 'hash') {
            const vtStats = response.analysis?.virustotal?.last_analysis_stats || null;
            const enginesObj = response.analysis?.virustotal?.malicious_engines || [];
            const meta = response.analysis?.virustotal?.meta || {};
            this.hashData = {
              virustotal: {
                vt_link: response.analysis?.virustotal?.vt_link || '',
                last_analysis_stats: vtStats,
                malicious_engines: enginesObj
                  .filter((e: any) => e.category === 'malicious' || e.category === 'suspicious')
                  .map((e: any) => ({
                    engine: e.engine || '',
                    result: e.category || ''
                  })),
                file_names: meta.file_names,
                file_size_readable: meta.file_size_readable || '',
                type_description: meta.type_description || ''
              },
            };
          }

          this.loading = false;
        },
        error: (err) => {
          console.error(err);
          this.errorMessage = 'Error scanning IOC. Please try again.';
          this.loading = false;
        }
      });
  }
}
