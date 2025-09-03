import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Navigation } from '@/components/Navigation';
import { Footer } from '@/components/Footer';
import { Scene3D } from '@/components/Scene3D';
import { LogVisualizer } from '@/components/LogVisualizer';
import { Button } from '@/components/ui/button';
import { ArrowLeft, Download, Copy, Check, Eye } from 'lucide-react';
import { apiService } from '@/services/api';
import { useToast } from '@/hooks/use-toast';

interface LogsPageProps {}

export const LogsPage: React.FC<LogsPageProps> = () => {
  const { analysisId } = useParams<{ analysisId: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [logs, setLogs] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const [copied, setCopied] = useState(false);
  const [showVisualizer, setShowVisualizer] = useState(false);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      const x = (e.clientX / window.innerWidth) * 2 - 1;
      const y = -(e.clientY / window.innerHeight) * 2 + 1;
      setMousePosition({ x, y });
    };

    window.addEventListener("mousemove", handleMouseMove);
    return () => window.removeEventListener("mousemove", handleMouseMove);
  }, []);

  useEffect(() => {
    if (!analysisId) {
      setError('No analysis ID provided');
      setLoading(false);
      return;
    }

    const fetchLogs = async () => {
      try {
        const response = await apiService.getAnalysisLogs(analysisId);
        setLogs(response.logs);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to fetch logs');
      } finally {
        setLoading(false);
      }
    };

    fetchLogs();
  }, [analysisId]);

  const handleCopyLogs = async () => {
    try {
      await navigator.clipboard.writeText(logs);
      setCopied(true);
      toast({
        title: "Logs copied!",
        description: "Analysis logs have been copied to your clipboard.",
      });
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      toast({
        title: "Copy failed",
        description: "Failed to copy logs to clipboard.",
        variant: "destructive",
      });
    }
  };

  const handleDownloadLogs = () => {
    const blob = new Blob([logs], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `analysis-logs-${analysisId}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    toast({
      title: "Download started",
      description: "Analysis logs are being downloaded.",
    });
  };

  const formatLogs = (rawLogs: string) => {
    return rawLogs.split('\n').map((line, index) => {
      let className = 'text-foreground/80';
      
      // Color different types of log lines
      if (line.includes('===')) {
        className = 'text-primary font-semibold';
      } else if (line.includes('CRITICAL:') || line.includes('[critical]')) {
        className = 'text-red-500 font-medium';
      } else if (line.includes('HIGH:') || line.includes('[high]')) {
        className = 'text-orange-500 font-medium';
      } else if (line.includes('MEDIUM:') || line.includes('[medium]')) {
        className = 'text-yellow-500 font-medium';
      } else if (line.includes('LOW:') || line.includes('[low]')) {
        className = 'text-blue-500 font-medium';
      } else if (line.includes('Found') && line.includes('vulnerability')) {
        className = 'text-green-400';
      } else if (line.includes('Analysis ID:') || line.includes('Project Path:')) {
        className = 'text-cyan-400';
      } else if (line.includes('Risk Score:') || line.includes('Security Posture:')) {
        className = 'text-purple-400';
      } else if (line.startsWith('  -')) {
        className = 'text-foreground/60 ml-4';
      }

      return (
        <div key={index} className={className}>
          {line || '\u00A0'} {/* Non-breaking space for empty lines */}
        </div>
      );
    });
  };

  return (
    <div className="min-h-screen bg-background">
      <Navigation />
      
      {/* Background particle effects */}
      <div className="fixed inset-0 particle-bg opacity-30" />
      
      {/* 3D Brain Animation */}
      <div className="fixed inset-0">
        <Scene3D mousePosition={mousePosition} className="w-full h-full" />
      </div>

      {/* Main Content */}
      <div className="relative z-10 pt-20 pb-8">
        <div className="container mx-auto px-6">
          {/* Header */}
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="flex items-center justify-between mb-8"
          >
            <div className="flex items-center space-x-4">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate('/')}
                className="flex items-center space-x-2"
              >
                <ArrowLeft className="w-4 h-4" />
                <span>Back to Home</span>
              </Button>
            </div>
            
            {!loading && !error && (
              <div className="flex items-center space-x-2">
                <Button
                  variant="default"
                  size="sm"
                  onClick={() => setShowVisualizer(true)}
                  className="flex items-center space-x-2 cyber-glow hover:shadow-[0_0_20px_hsl(var(--cyber-green)/0.6)] transition-all duration-300"
                >
                  <Eye className="w-4 h-4" />
                  <span>Visualize Logs</span>
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCopyLogs}
                  className="flex items-center space-x-2"
                >
                  {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  <span>{copied ? 'Copied!' : 'Copy'}</span>
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleDownloadLogs}
                  className="flex items-center space-x-2"
                >
                  <Download className="w-4 h-4" />
                  <span>Download</span>
                </Button>
              </div>
            )}
          </motion.div>

          {/* Analysis ID Display */}
          {analysisId && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.1 }}
              className="glassmorphism border border-primary/30 rounded-lg p-4 mb-6"
            >
              <div className="text-sm text-foreground/70 mb-1">Analysis ID</div>
              <div className="font-mono text-primary">{analysisId}</div>
            </motion.div>
          )}

          {/* Content */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="glassmorphism border border-primary/20 rounded-lg overflow-hidden"
          >
            {loading && (
              <div className="flex items-center justify-center p-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                <span className="ml-3 text-foreground/70">Loading logs...</span>
              </div>
            )}

            {error && (
              <div className="p-8 text-center">
                <div className="text-red-500 mb-2">Error Loading Logs</div>
                <div className="text-foreground/60">{error}</div>
              </div>
            )}

            {!loading && !error && (
              <div className="bg-black/20 p-6">
                <div className="font-mono text-sm leading-relaxed overflow-auto max-h-[70vh]">
                  {formatLogs(logs)}
                </div>
              </div>
            )}
          </motion.div>
        </div>
      </div>

      <Footer />
      
      {/* Log Visualizer Modal */}
      {showVisualizer && analysisId && (
        <LogVisualizer
          rawLogs={logs}
          analysisId={analysisId}
          onClose={() => setShowVisualizer(false)}
        />
      )}
    </div>
  );
};

export default LogsPage;
