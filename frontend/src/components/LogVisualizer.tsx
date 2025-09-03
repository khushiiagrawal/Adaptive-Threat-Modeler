import React, { useState, useMemo, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ChevronDown, 
  ChevronRight, 
  Search, 
  Copy,
  Download,
  X,
  AlertTriangle,
  Info,
  CheckCircle,
  XCircle,
  Code,
  FileText,
  Activity,
  Shield,
  Zap,
  TrendingUp,
  Clock,
  Target
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { LogParser, type ParsedLogs, type LogSection } from '@/utils/logParser';

interface LogVisualizerProps {
  rawLogs: string;
  analysisId: string;
  onClose: () => void;
}

export const LogVisualizer: React.FC<LogVisualizerProps> = ({
  rawLogs,
  analysisId,
  onClose
}) => {
  const { toast } = useToast();
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedSections, setExpandedSections] = useState<Set<number>>(new Set([0]));
  
  const parsedLogs = useMemo(() => {
    return LogParser.parse(rawLogs);
  }, [rawLogs]);

  const vulnerabilities = useMemo(() => {
    return LogParser.extractVulnerabilities(parsedLogs.sections);
  }, [parsedLogs.sections]);

  const filteredSections = useMemo(() => {
    return parsedLogs.sections.filter(section => {
      // Search filter only
      if (searchTerm && !section.content.toLowerCase().includes(searchTerm.toLowerCase()) && 
          !section.title.toLowerCase().includes(searchTerm.toLowerCase())) {
        return false;
      }
      
      return true;
    });
  }, [parsedLogs.sections, searchTerm]);



  // Calculate statistics
  const stats = useMemo(() => {
    const severityCounts = vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const totalFiles = new Set(vulnerabilities.map(v => v.file).filter(Boolean)).size;
    
    return {
      total: vulnerabilities.length,
      critical: severityCounts.critical || 0,
      high: severityCounts.high || 0,
      medium: severityCounts.medium || 0,
      low: severityCounts.low || 0,
      files: totalFiles,
      sections: parsedLogs.sections.length
    };
  }, [vulnerabilities, parsedLogs.sections]);

  const toggleSection = (index: number) => {
    const newExpanded = new Set(expandedSections);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedSections(newExpanded);
  };

  const getSectionIcon = (section: LogSection) => {
    switch (section.type) {
      case 'header':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'vulnerability':
        return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'json':
        return <Code className="w-4 h-4 text-blue-400" />;
      case 'summary':
        return <Info className="w-4 h-4 text-cyan-400" />;
      default:
        return <FileText className="w-4 h-4 text-foreground/60" />;
    }
  };

  const getSeverityColor = (severity?: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/20 border-red-500/50 text-red-400';
      case 'high':
        return 'bg-orange-500/20 border-orange-500/50 text-orange-400';
      case 'medium':
        return 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400';
      case 'low':
        return 'bg-blue-500/20 border-blue-500/50 text-blue-400';
      default:
        return 'bg-foreground/10 border-foreground/20 text-foreground/60';
    }
  };

  const handleCopySection = async (content: string, title: string) => {
    try {
      await navigator.clipboard.writeText(content);
      toast({
        title: "Section copied!",
        description: `"${title}" has been copied to your clipboard.`,
      });
    } catch (err) {
      toast({
        title: "Copy failed",
        description: "Failed to copy section content.",
        variant: "destructive",
      });
    }
  };

  const handleDownloadParsed = () => {
    const data = {
      metadata: parsedLogs.metadata,
      vulnerabilities,
      sections: parsedLogs.sections.map(s => ({
        title: s.title,
        type: s.type,
        severity: s.severity,
        content: s.content,
        data: s.data
      }))
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `parsed-logs-${analysisId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    toast({
      title: "Download started",
      description: "Parsed log data is being downloaded.",
    });
  };

  const renderJsonData = (data: any, depth = 0) => {
    if (typeof data !== 'object' || data === null) {
      return (
        <span className="text-green-400">
          {typeof data === 'string' ? `"${data}"` : String(data)}
        </span>
      );
    }

    if (Array.isArray(data)) {
      return (
        <div className="ml-4">
          <span className="text-foreground/60">[</span>
          {data.map((item, index) => (
            <div key={index} className="ml-4">
              {renderJsonData(item, depth + 1)}
              {index < data.length - 1 && <span className="text-foreground/60">,</span>}
            </div>
          ))}
          <span className="text-foreground/60">]</span>
        </div>
      );
    }

    return (
      <div className="ml-4">
        <span className="text-foreground/60">{'{'}</span>
        {Object.entries(data).map(([key, value], index, arr) => (
          <div key={key} className="ml-4">
            <span className="text-blue-300">"{key}"</span>
            <span className="text-foreground/60">: </span>
            {renderJsonData(value, depth + 1)}
            {index < arr.length - 1 && <span className="text-foreground/60">,</span>}
          </div>
        ))}
        <span className="text-foreground/60">{'}'}</span>
      </div>
    );
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/90 backdrop-blur-md flex items-center justify-center p-4">
      {/* Animated background particles */}
      <div className="absolute inset-0 overflow-hidden">
        {[...Array(20)].map((_, i) => (
          <motion.div
            key={i}
            className="absolute w-1 h-1 bg-primary/30 rounded-full"
            animate={{
              x: [Math.random() * window.innerWidth, Math.random() * window.innerWidth],
              y: [Math.random() * window.innerHeight, Math.random() * window.innerHeight],
            }}
            transition={{
              duration: 10 + Math.random() * 20,
              repeat: Infinity,
              repeatType: "reverse",
            }}
          />
        ))}
      </div>

      <motion.div
        initial={{ opacity: 0, scale: 0.9, rotateX: -10 }}
        animate={{ opacity: 1, scale: 1, rotateX: 0 }}
        exit={{ opacity: 0, scale: 0.9, rotateX: 10 }}
        transition={{ type: "spring", damping: 20, stiffness: 300 }}
        className="relative w-full max-w-7xl h-[95vh] glassmorphism border border-primary/40 rounded-xl overflow-hidden flex flex-col"
      >
        
        {/* Header with enhanced design */}
        <div className="relative flex items-center justify-between p-6 border-b border-primary/30 bg-gradient-to-r from-background/80 to-background/60">
          <div className="flex items-center space-x-6">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/30">
              <Shield className="w-8 h-8 text-primary" />
            </div>
            <div>
              <h2 className="text-3xl font-bold cyber-text-glow flex items-center space-x-3">
                <span>Advanced Log Analyzer</span>
                <Activity className="w-6 h-6 text-green-400" />
              </h2>
              <p className="text-sm text-foreground/60 mt-1">
                Real-time security analysis visualization • ID: {analysisId}
              </p>
            </div>
          </div>
          
          <div className="flex items-center space-x-3">
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownloadParsed}
              className="flex items-center space-x-2 hover:bg-primary/10 border-primary/30"
            >
              <Download className="w-4 h-4" />
              <span>Export Analysis</span>
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={onClose}
              className="flex items-center space-x-2 hover:bg-red-500/10 text-red-400"
            >
              <X className="w-5 h-5" />
            </Button>
          </div>
        </div>

        {/* Enhanced Statistics Dashboard */}
        <div className="p-6 border-b border-primary/30 bg-gradient-to-br from-background/70 to-background/50">
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
            {/* Vulnerability Stats */}
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
              <AlertTriangle className="w-6 h-6 text-red-400 mb-2" />
              <div className="text-2xl font-bold text-red-400">{stats.critical + stats.high}</div>
              <div className="text-xs text-red-300/80">Critical/High</div>
            </div>

            <div className="bg-primary/10 border border-primary/30 rounded-lg p-4">
              <Target className="w-6 h-6 text-primary mb-2" />
              <div className="text-2xl font-bold text-primary">{stats.total}</div>
              <div className="text-xs text-primary/80">Total Issues</div>
            </div>

            <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
              <FileText className="w-6 h-6 text-blue-400 mb-2" />
              <div className="text-2xl font-bold text-blue-400">{stats.files}</div>
              <div className="text-xs text-blue-300/80">Files Scanned</div>
            </div>

            <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-4">
              <Code className="w-6 h-6 text-purple-400 mb-2" />
              <div className="text-xl font-bold text-purple-400">
                {parsedLogs.metadata.languages?.join(', ') || 'Mixed'}
              </div>
              <div className="text-xs text-purple-300/80">Languages</div>
            </div>

            <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
              <Clock className="w-6 h-6 text-green-400 mb-2" />
              <div className="text-lg font-bold text-green-400">
                {parsedLogs.metadata.processingTime || 'N/A'}
              </div>
              <div className="text-xs text-green-300/80">Process Time</div>
            </div>

            <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-lg p-4">
              <TrendingUp className="w-6 h-6 text-cyan-400 mb-2" />
              <div className="text-2xl font-bold text-cyan-400">{stats.sections}</div>
              <div className="text-xs text-cyan-300/80">Log Sections</div>
            </div>
          </div>

          {/* Risk Level Indicator */}
          <div className="mt-6 p-4 bg-gradient-to-r from-red-500/10 via-yellow-500/10 to-green-500/10 border border-primary/20 rounded-lg">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm font-medium">Security Risk Assessment</span>
              <Zap className="w-4 h-4 text-yellow-400" />
            </div>
            
            <div className="flex space-x-1 h-3 bg-background/50 rounded-full overflow-hidden mb-3">
              <motion.div 
                className="bg-red-500" 
                style={{ width: `${(stats.critical / Math.max(stats.total, 1)) * 100}%` }}
                initial={{ width: 0 }}
                animate={{ width: `${(stats.critical / Math.max(stats.total, 1)) * 100}%` }}
                transition={{ duration: 1, delay: 0.5 }}
              />
              <motion.div 
                className="bg-orange-500" 
                style={{ width: `${(stats.high / Math.max(stats.total, 1)) * 100}%` }}
                initial={{ width: 0 }}
                animate={{ width: `${(stats.high / Math.max(stats.total, 1)) * 100}%` }}
                transition={{ duration: 1, delay: 0.7 }}
              />
              <motion.div 
                className="bg-yellow-500" 
                style={{ width: `${(stats.medium / Math.max(stats.total, 1)) * 100}%` }}
                initial={{ width: 0 }}
                animate={{ width: `${(stats.medium / Math.max(stats.total, 1)) * 100}%` }}
                transition={{ duration: 1, delay: 0.9 }}
              />
              <motion.div 
                className="bg-blue-500" 
                style={{ width: `${(stats.low / Math.max(stats.total, 1)) * 100}%` }}
                initial={{ width: 0 }}
                animate={{ width: `${(stats.low / Math.max(stats.total, 1)) * 100}%` }}
                transition={{ duration: 1, delay: 1.1 }}
              />
            </div>
            
            {/* Legend */}
            <div className="flex items-center justify-between text-xs text-foreground/70">
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-1">
                  <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                  <span>Critical ({stats.critical})</span>
                </div>
                <div className="flex items-center space-x-1">
                  <div className="w-2 h-2 bg-orange-500 rounded-full"></div>
                  <span>High ({stats.high})</span>
                </div>
                <div className="flex items-center space-x-1">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full"></div>
                  <span>Medium ({stats.medium})</span>
                </div>
                <div className="flex items-center space-x-1">
                  <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
                  <span>Low ({stats.low})</span>
                </div>
              </div>
              <span className="text-foreground/50">Total: {stats.total}</span>
            </div>
          </div>
        </div>

        {/* Enhanced Search */}
        <div className="p-4 border-b border-primary/20 bg-background/30">
          <div className="relative max-w-md">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-foreground/40" />
            <Input
              placeholder="Search through analysis logs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 bg-background/50 border-primary/30 focus:border-primary/60 focus:ring-1 focus:ring-primary/40"
            />
          </div>
        </div>

        {/* Enhanced Content */}
        <div className="flex-1 overflow-auto p-6 scrollbar-hide">
          <div className="space-y-4">
            {filteredSections.map((section, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ 
                  delay: index * 0.1, 
                  type: "spring", 
                  stiffness: 100,
                  damping: 15
                }}
                className={`border rounded-xl overflow-hidden group relative ${getSeverityColor(section.severity)}`}
              >
                {/* Section Header */}
                <div
                  className="flex items-center justify-between p-5 cursor-pointer relative z-10"
                  onClick={() => toggleSection(index)}
                >
                  <div className="flex items-center space-x-4">
                    <motion.div
                      animate={{ rotate: expandedSections.has(index) ? 90 : 0 }}
                      transition={{ duration: 0.3 }}
                    >
                      <ChevronRight className="w-5 h-5" />
                    </motion.div>
                    
                    <motion.div
                      animate={{ 
                        scale: expandedSections.has(index) ? 1.1 : 1,
                        rotate: expandedSections.has(index) ? 5 : 0
                      }}
                      transition={{ duration: 0.3 }}
                    >
                      {getSectionIcon(section)}
                    </motion.div>
                    
                    <div>
                      <h3 className="font-bold text-lg">{section.title}</h3>
                      {section.type === 'json' && (
                        <p className="text-xs text-foreground/60 mt-1">
                          Interactive JSON data • Click to explore
                        </p>
                      )}
                    </div>
                    
                    {section.severity && (
                      <Badge 
                        variant="outline" 
                        className={`text-xs capitalize font-semibold ${
                          section.severity === 'critical' ? 'border-red-500/50 text-red-400 bg-red-500/10' :
                          section.severity === 'high' ? 'border-orange-500/50 text-orange-400 bg-orange-500/10' :
                          section.severity === 'medium' ? 'border-yellow-500/50 text-yellow-400 bg-yellow-500/10' :
                          'border-blue-500/50 text-blue-400 bg-blue-500/10'
                        }`}
                      >
                        {section.severity}
                      </Badge>
                    )}
                  </div>
                  
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleCopySection(section.content, section.title);
                    }}
                    className="opacity-60 hover:opacity-100 transition-opacity"
                  >
                    <Copy className="w-4 h-4" />
                  </Button>
                </div>

                {/* Enhanced Section Content */}
                <AnimatePresence>
                  {expandedSections.has(index) && (
                    <motion.div
                      initial={{ height: 0, opacity: 0, y: -20 }}
                      animate={{ height: 'auto', opacity: 1, y: 0 }}
                      exit={{ height: 0, opacity: 0, y: -10 }}
                      transition={{ 
                        duration: 0.4, 
                        type: "spring", 
                        stiffness: 100,
                        damping: 20
                      }}
                      className="border-t border-current/30 relative overflow-hidden"
                    >
                      {/* Content background effect */}
                      <div className="absolute inset-0 bg-gradient-to-br from-background/80 via-background/60 to-background/40" />
                      
                      <div className="relative z-10 p-6">
                        {section.type === 'json' && section.data ? (
                          <div className="relative">
                            <div className="absolute top-0 right-0 flex items-center space-x-2 mb-4">
                              <Badge variant="outline" className="text-xs bg-blue-500/10 border-blue-500/30 text-blue-400">
                                JSON Data
                              </Badge>
                            </div>
                            <div className="bg-black/40 rounded-lg p-4 border border-primary/20 font-mono text-sm overflow-auto max-h-96 mt-8 scrollbar-hide">
                              <motion.div
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                transition={{ delay: 0.2, duration: 0.5 }}
                              >
                                {renderJsonData(section.data)}
                              </motion.div>
                            </div>
                          </div>
                        ) : (
                          <div className="relative">
                            <div className="absolute top-0 right-0 flex items-center space-x-2 mb-4">
                              <Badge variant="outline" className="text-xs bg-foreground/10 border-foreground/20 text-foreground/60">
                                Log Output
                              </Badge>
                            </div>
                            <div className="bg-black/40 rounded-lg p-4 border border-primary/20 mt-8">
                              <motion.pre 
                                className="font-mono text-sm whitespace-pre-wrap overflow-auto max-h-96 text-foreground/90 leading-relaxed scrollbar-hide"
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: 0.2, duration: 0.5 }}
                              >
                                {section.content}
                              </motion.pre>
                            </div>
                          </div>
                        )}
                        
                        {/* Section metadata */}
                        <div className="mt-4 pt-4 border-t border-current/10 flex items-center justify-between text-xs text-foreground/50">
                          <div className="flex items-center space-x-4">
                            <span>Type: {section.type}</span>
                            <span>Lines: {section.content.split('\n').length}</span>
                            {section.severity && <span>Severity: {section.severity}</span>}
                          </div>
                          <div className="flex items-center space-x-2">
                            <div className="w-2 h-2 bg-primary/60 rounded-full" />
                            <span>Live Analysis</span>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            ))}
          </div>
          
          {filteredSections.length === 0 && (
            <div className="text-center py-12">
              <XCircle className="w-12 h-12 text-foreground/40 mx-auto mb-4" />
              <p className="text-foreground/60">No log sections match your current filters.</p>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
};
