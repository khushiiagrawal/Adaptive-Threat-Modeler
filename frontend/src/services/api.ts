// API service for communicating with the Adaptive Threat Modeler backend

export interface AnalysisRequest {
    repo_url?: string;
    branch?: string;
    file?: File;
}

export interface ProjectInfo {
    languages: string[];
    frameworks: string[];
    services: ServiceInfo[];
    dependencies: Record<string, string>;
    config_files: string[];
}

export interface ServiceInfo {
    name: string;
    type: string;
    endpoints: EndpointInfo[];
    config: Record<string, string>;
}

export interface EndpointInfo {
    path: string;
    method: string;
    handler: string;
    params: string[];
    auth_required: boolean;
}

export interface Vulnerability {
    id: string;
    title: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    category: string;
    cwe?: string;
    owasp?: string;
    location: {
        file: string;
        line: number;
        column: number;
        end_line?: number;
        end_column?: number;
        function?: string;
        class?: string;
    };
    evidence: string;
    impact: string;
    remediation: string[];
    autofix?: {
        description: string;
        old_code: string;
        new_code: string;
        confidence: 'high' | 'medium' | 'low';
    };
    references: string[];
    metadata: Record<string, string>;
}

export interface ThreatMap {
    components: Component[];
    flows: DataFlow[];
    trust_zones: TrustZone[];
    assets: Asset[];
}

export interface Component {
    id: string;
    name: string;
    type: string;
    trust_zone: string;
    properties: Record<string, string>;
    threats: string[];
}

export interface DataFlow {
    id: string;
    source: string;
    destination: string;
    protocol: string;
    data: string;
    encrypted: boolean;
    threats: string[];
    properties: Record<string, string>;
}

export interface TrustZone {
    id: string;
    name: string;
    trust_level: string;
    description: string;
    components: string[];
}

export interface Asset {
    id: string;
    name: string;
    type: string;
    sensitivity: string;
    components: string[];
    threats: string[];
}

export interface Summary {
    total_vulnerabilities: number;
    severity_breakdown: Record<string, number>;
    category_breakdown: Record<string, number>;
    risk_score: number;
    security_posture: string;
    top_risks: string[];
}

export interface AnalysisResult {
    id: string;
    timestamp: string;
    project_info: ProjectInfo;
    vulnerabilities: Vulnerability[];
    threat_map: ThreatMap;
    summary: Summary;
    recommendations: string[];
    status: 'processing' | 'completed' | 'failed';
    processing_time: string;
}

export interface AnalysisStatus {
    analysis_id: string;
    status: 'processing' | 'completed' | 'failed';
    progress: number;
}

class ApiService {
    // Analysis endpoints
    async analyzeGitHubRepo(repoUrl: string, branch?: string): Promise<{ analysis_id: string; status: string; message: string }> {
        const response = await fetch('/api/v1/analyze/github', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                repo_url: repoUrl,
                branch,
            }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to start analysis');
        }

        return response.json();
    }

    async analyzeUpload(file: File): Promise<{ analysis_id: string; status: string; message: string; filename: string }> {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch('/api/v1/analyze/upload', {
            method: 'POST',
            body: formData,
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to start analysis');
        }

        return response.json();
    }

    async getAnalysisResult(analysisId: string): Promise<AnalysisResult> {
        const response = await fetch(`/api/v1/analysis/${analysisId}`);

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to get analysis result');
        }

        return response.json();
    }

    async getAnalysisStatus(analysisId: string): Promise<AnalysisStatus> {
        const response = await fetch(`/api/v1/analysis/${analysisId}/status`);

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || 'Failed to get analysis status');
        }

        return response.json();
    }

    async checkHealth(): Promise<{ status: string; service: string }> {
        const response = await fetch('/health');

        if (!response.ok) {
            throw new Error(`Backend returned status ${response.status}`);
        }

        return response.json();
    }

    // Utility method to poll for analysis completion
    async pollAnalysisStatus(
        analysisId: string,
        onStatusUpdate?: (status: AnalysisStatus) => void,
        maxAttempts = 60,
        intervalMs = 5000
    ): Promise<AnalysisResult> {
        let attempts = 0;

        const poll = async (): Promise<AnalysisResult> => {
            if (attempts >= maxAttempts) {
                throw new Error('Analysis timeout - maximum polling attempts reached');
            }

            attempts++;
            const status = await this.getAnalysisStatus(analysisId);

            if (onStatusUpdate) {
                onStatusUpdate(status);
            }

            if (status.status === 'completed') {
                return this.getAnalysisResult(analysisId);
            } else if (status.status === 'failed') {
                throw new Error('Analysis failed');
            } else {
                // Still processing, wait and poll again
                await new Promise(resolve => setTimeout(resolve, intervalMs));
                return poll();
            }
        };

        return poll();
    }
}

export const apiService = new ApiService();
export default apiService;
