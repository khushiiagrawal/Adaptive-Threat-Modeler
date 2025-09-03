import { useState, useCallback } from 'react';
import { apiService, AnalysisResult, AnalysisStatus } from '@/services/api';

interface UseAnalysisReturn {
    // State
    isLoading: boolean;
    error: string | null;
    analysisResult: AnalysisResult | null;
    analysisStatus: AnalysisStatus | null;
    analysisId: string | null;

    // Actions
    analyzeGitHubRepo: (repoUrl: string, branch?: string) => Promise<void>;
    analyzeFile: (file: File) => Promise<void>;
    checkAnalysisStatus: (id: string) => Promise<void>;
    getAnalysisResult: (id: string) => Promise<void>;
    clearResults: () => void;
    checkBackendHealth: () => Promise<boolean>;
}

export const useAnalysis = (): UseAnalysisReturn => {
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
    const [analysisStatus, setAnalysisStatus] = useState<AnalysisStatus | null>(null);
    const [analysisId, setAnalysisId] = useState<string | null>(null);

    const clearResults = useCallback(() => {
        setAnalysisResult(null);
        setAnalysisStatus(null);
        setAnalysisId(null);
        setError(null);
    }, []);

    const analyzeGitHubRepo = useCallback(async (repoUrl: string, branch?: string) => {
        setIsLoading(true);
        setError(null);
        clearResults();

        try {
            const response = await apiService.analyzeGitHubRepo(repoUrl, branch);
            setAnalysisId(response.analysis_id);

            // Start polling for status
            const result = await apiService.pollAnalysisStatus(
                response.analysis_id,
                (status) => {
                    setAnalysisStatus(status);
                }
            );

            setAnalysisResult(result);
            setAnalysisStatus({
                analysis_id: response.analysis_id,
                status: 'completed',
                progress: 100
            });
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Analysis failed');
        } finally {
            setIsLoading(false);
        }
    }, [clearResults]);

    const analyzeFile = useCallback(async (file: File) => {
        setIsLoading(true);
        setError(null);
        clearResults();

        try {
            const response = await apiService.analyzeUpload(file);
            setAnalysisId(response.analysis_id);

            // Start polling for status
            const result = await apiService.pollAnalysisStatus(
                response.analysis_id,
                (status) => {
                    setAnalysisStatus(status);
                }
            );

            setAnalysisResult(result);
            setAnalysisStatus({
                analysis_id: response.analysis_id,
                status: 'completed',
                progress: 100
            });
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Analysis failed');
        } finally {
            setIsLoading(false);
        }
    }, [clearResults]);

    const checkAnalysisStatus = useCallback(async (id: string) => {
        try {
            const status = await apiService.getAnalysisStatus(id);
            setAnalysisStatus(status);
            setAnalysisId(id);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to check status');
        }
    }, []);

    const getAnalysisResult = useCallback(async (id: string) => {
        setIsLoading(true);
        setError(null);

        try {
            const result = await apiService.getAnalysisResult(id);
            setAnalysisResult(result);
            setAnalysisId(id);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to get results');
        } finally {
            setIsLoading(false);
        }
    }, []);

    const checkBackendHealth = useCallback(async (): Promise<boolean> => {
        try {
            await apiService.checkHealth();
            return true;
        } catch {
            return false;
        }
    }, []);

    return {
        // State
        isLoading,
        error,
        analysisResult,
        analysisStatus,
        analysisId,

        // Actions
        analyzeGitHubRepo,
        analyzeFile,
        checkAnalysisStatus,
        getAnalysisResult,
        clearResults,
        checkBackendHealth,
    };
};
