// Log parser utility to extract structured data from analysis logs

export interface LogSection {
    title: string;
    type: 'header' | 'info' | 'vulnerability' | 'summary' | 'json';
    content: string;
    data?: any;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    timestamp?: string;
    level: number; // For hierarchical display
}

export interface ParsedLogs {
    sections: LogSection[];
    metadata: {
        analysisId?: string;
        projectPath?: string;
        totalVulnerabilities?: number;
        languages?: string[];
        frameworks?: string[];
        processingTime?: string;
    };
}

export class LogParser {
    static parse(rawLogs: string): ParsedLogs {
        const lines = rawLogs.split('\n');
        const sections: LogSection[] = [];
        const metadata: ParsedLogs['metadata'] = {};

        let currentSection: LogSection | null = null;
        let jsonBuffer = '';
        let inJsonBlock = false;
        let bracketCount = 0;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();

            // Skip empty lines
            if (!line && !inJsonBlock) continue;

            // Detect section headers
            if (line.startsWith('===') && line.endsWith('===')) {
                // Save previous section
                if (currentSection) {
                    sections.push(currentSection);
                }

                // Create new section
                const title = line.replace(/=/g, '').trim();
                currentSection = {
                    title,
                    type: this.getSectionType(title),
                    content: '',
                    level: 0
                };
                continue;
            }

            // Detect JSON blocks
            if (line.includes('{') || inJsonBlock) {
                if (!inJsonBlock) {
                    jsonBuffer = '';
                    inJsonBlock = true;
                    bracketCount = 0;
                }

                // Count brackets to detect end of JSON
                for (const char of line) {
                    if (char === '{') bracketCount++;
                    if (char === '}') bracketCount--;
                }

                jsonBuffer += line + '\n';

                // End of JSON block
                if (bracketCount <= 0 && inJsonBlock) {
                    inJsonBlock = false;
                    try {
                        const jsonData = JSON.parse(jsonBuffer.trim());
                        if (currentSection) {
                            currentSection.type = 'json';
                            currentSection.data = jsonData;
                            currentSection.content = JSON.stringify(jsonData, null, 2);
                        }
                    } catch (e) {
                        // If JSON parsing fails, treat as regular content
                        if (currentSection) {
                            currentSection.content += jsonBuffer;
                        }
                    }
                    jsonBuffer = '';
                }
                continue;
            }

            // Extract metadata
            if (line.includes('Analysis ID:')) {
                metadata.analysisId = line.split('Analysis ID:')[1]?.trim();
            } else if (line.includes('Project Path:')) {
                metadata.projectPath = line.split('Project Path:')[1]?.trim();
            } else if (line.includes('Total vulnerabilities found:')) {
                const match = line.match(/Total vulnerabilities found: (\d+)/);
                if (match) {
                    metadata.totalVulnerabilities = parseInt(match[1]);
                }
            } else if (line.includes('Detected Languages:')) {
                const languagesStr = line.split('Detected Languages:')[1]?.trim();
                if (languagesStr) {
                    metadata.languages = this.parseArrayString(languagesStr);
                }
            } else if (line.includes('Detected Frameworks:')) {
                const frameworksStr = line.split('Detected Frameworks:')[1]?.trim();
                if (frameworksStr) {
                    metadata.frameworks = this.parseArrayString(frameworksStr);
                }
            } else if (line.includes('Processing Time:')) {
                metadata.processingTime = line.split('Processing Time:')[1]?.trim();
            }

            // Add line to current section
            if (currentSection && !inJsonBlock) {
                // Detect severity levels
                if (line.includes('[critical]') || line.includes('CRITICAL:')) {
                    currentSection.severity = 'critical';
                } else if (line.includes('[high]') || line.includes('HIGH:')) {
                    currentSection.severity = 'high';
                } else if (line.includes('[medium]') || line.includes('MEDIUM:')) {
                    currentSection.severity = 'medium';
                } else if (line.includes('[low]') || line.includes('LOW:')) {
                    currentSection.severity = 'low';
                }

                currentSection.content += line + '\n';
            }
        }

        // Add final section
        if (currentSection) {
            sections.push(currentSection);
        }

        return { sections, metadata };
    }

    private static getSectionType(title: string): LogSection['type'] {
        const lowerTitle = title.toLowerCase();

        if (lowerTitle.includes('started') || lowerTitle.includes('completed')) {
            return 'header';
        } else if (lowerTitle.includes('vulnerability') || lowerTitle.includes('security')) {
            return 'vulnerability';
        } else if (lowerTitle.includes('summary') || lowerTitle.includes('analysis')) {
            return 'summary';
        } else if (lowerTitle.includes('json') || lowerTitle.includes('ast')) {
            return 'json';
        }

        return 'info';
    }

    private static parseArrayString(str: string): string[] {
        // Handle formats like "[go javascript]" or "go, javascript"
        const cleaned = str.replace(/[\[\]]/g, '').trim();
        if (cleaned.includes(',')) {
            return cleaned.split(',').map(s => s.trim()).filter(s => s);
        }
        return cleaned.split(/\s+/).filter(s => s);
    }

    static extractVulnerabilities(sections: LogSection[]): Array<{
        title: string;
        severity: string;
        description: string;
        file?: string;
        line?: number;
    }> {
        const vulnerabilities: Array<{
            title: string;
            severity: string;
            description: string;
            file?: string;
            line?: number;
        }> = [];

        for (const section of sections) {
            if (section.type === 'json' && section.data) {
                try {
                    // Check if it's the AST-style JSON output
                    if (section.data.results && Array.isArray(section.data.results)) {
                        for (const result of section.data.results) {
                            vulnerabilities.push({
                                title: result.check_id || 'Unknown Vulnerability',
                                severity: (result.extra?.severity || 'info').toLowerCase(),
                                description: result.extra?.message || 'No description available',
                                file: result.path,
                                line: result.start?.line
                            });
                        }
                    }
                } catch (e) {
                    console.warn('Failed to parse vulnerability data:', e);
                }
            }
        }

        return vulnerabilities;
    }
}
