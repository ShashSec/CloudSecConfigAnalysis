import json
import asyncio
import logging
from pathlib import Path
from typing import List, Dict
from datetime import datetime
from dataclasses import asdict

from models.resource import Resource
from registry.rule_registry import SecurityRuleRegistry
from registry.rule_loader import RuleLoader
from engine.analysis_engine import SecurityAnalysisEngine

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    def __init__(self, resources_file: str):
        self.resources_file = Path(resources_file)
        self.registry = SecurityRuleRegistry()
        self.loader = RuleLoader(self.registry)
        self.engine = SecurityAnalysisEngine(self.registry)

    def load_resources(self) -> List[Resource]:
        """Load resources from JSON file and convert to Resource objects"""
        try:
            with open(self.resources_file, 'r') as f:
                data = json.load(f)
                resources_list = data.get('resources', [])
                
            # Convert each dictionary to Resource object
            resources = []
            for item in resources_list:
                if self._validate_resource_json(item):
                    resource = Resource(
                        name=item.get('name'),
                        type=item.get('type'),
                        properties=item
                    )
                    resources.append(resource)
                else:
                    logging.warning(f"Skipping invalid resource: {item.get('name', 'unknown')}")
            
            logging.info(f"Loaded {len(resources)} resources")
            return resources
        except Exception as e:
            logging.error(f"Error loading resources: {str(e)}")
            raise        
        except FileNotFoundError:
            logger.error(f"Resources file not found: {self.resources_file}")
            raise
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in resources file: {self.resources_file}")
            raise
        except KeyError as e:
            logger.error(f"Missing required field in resources file: {e}")
            raise

    def _validate_resource_json(self, item: Dict) -> bool:
        """Validate that the JSON has the minimum required fields."""
        required_fields = ['type', 'name']
        return all(field in item for field in required_fields)

    async def analyze_resources(self) -> Dict:
        """Analyze all resources and generate findings report."""
        try:
            # Load rules
            logger.info("Loading security rules...")
            self.loader.load_all_rules()
            
            # Load resources
            logger.info("Loading resources from file...")
            resources = self.load_resources()
            
            # Analyze each resource
            logger.info("Starting security analysis...")
            all_findings = []
            failed_resources = []
            
            for resource in resources:
                try:
                    logger.info(f"Analyzing resource: {resource.name} ({resource.type})")
                    findings = await self.engine.analyze_resource(resource)
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error(f"Failed to analyze resource {resource.name}: {e}")
                    failed_resources.append({
                        'name': resource.name,
                        'type': resource.type,
                        'error': str(e)
                    })
            
            # Generate report
            report = {
                'timestamp': datetime.now().isoformat(),
                'total_resources_analyzed': len(resources),
                'successful_analyses': len(resources) - len(failed_resources),
                'failed_analyses': len(failed_resources),
                'failed_resources': failed_resources,
                'total_findings': len(all_findings),
                'findings_by_severity': self._group_findings_by_severity(all_findings),
                'findings_by_resource': self._group_findings_by_resource(all_findings),
                'detailed_findings': [asdict(finding) for finding in all_findings]
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            raise
        
    def _group_findings_by_severity(self, findings):
        """Group findings by severity level."""
        severity_groups = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for finding in findings:
            severity_groups[finding.severity].append(asdict(finding))
        return severity_groups

    def _group_findings_by_resource(self, findings):
        """Group findings by resource type."""
        resource_groups = {}
        for finding in findings:
            if finding.resource_type not in resource_groups:
                resource_groups[finding.resource_type] = []
            resource_groups[finding.resource_type].append(asdict(finding))
        return resource_groups

    def save_report(self, report: Dict, output_file: str):
        """Save the analysis report to a JSON file."""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Report saved to: {output_path}")
            
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            raise

async def main():
    try:
        # Initialize the analyzer
        analyzer = SecurityAnalyzer('data/resources.json')
        
        # Run the analysis
        report = await analyzer.analyze_resources()
        
        # Save the report
        analyzer.save_report(report, 'output/security_report.json')
        
        # Print summary
        print("\nAnalysis Summary:")
        print(f"Total resources analyzed: {report['total_resources_analyzed']}")
        print(f"Total findings: {report['total_findings']}")
        print("\nFindings by Severity:")
        for severity, findings in report['findings_by_severity'].items():
            print(f"{severity}: {len(findings)} findings")
            
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())