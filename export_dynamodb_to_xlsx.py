#!/usr/bin/env python3

import json
import pandas as pd
from datetime import datetime
import sys

def convert_dynamodb_to_dict(item):
    """Convert DynamoDB item format to regular dictionary"""
    result = {}
    for key, value in item.items():
        if 'S' in value:  # String
            result[key] = value['S']
        elif 'N' in value:  # Number
            result[key] = float(value['N']) if '.' in value['N'] else int(value['N'])
        elif 'SS' in value:  # String Set
            result[key] = ', '.join(value['SS'])
        elif 'NS' in value:  # Number Set
            result[key] = ', '.join(value['NS'])
        elif 'L' in value:  # List
            result[key] = str(value['L'])
        elif 'M' in value:  # Map
            result[key] = str(value['M'])
        elif 'BOOL' in value:  # Boolean
            result[key] = value['BOOL']
        elif 'NULL' in value:  # Null
            result[key] = None
        else:
            result[key] = str(value)
    return result

def create_schema_dataframe():
    """Create schema information DataFrame"""
    schema_data = [
        {
            'Attribute_Name': 'object_id',
            'Type': 'String (S)',
            'Key_Type': 'HASH (Primary Key)',
            'Description': 'Unique identifier for the threat intelligence object'
        },
        {
            'Attribute_Name': 'object_type',
            'Type': 'String (S)',
            'Key_Type': 'RANGE (Sort Key)',
            'Description': 'Type of threat intelligence object (indicator, malware, etc.)'
        },
        {
            'Attribute_Name': 'confidence',
            'Type': 'Number (N)',
            'Key_Type': 'GSI Range Key',
            'Description': 'Confidence score for the threat intelligence'
        },
        {
            'Attribute_Name': 'created_date',
            'Type': 'String (S)',
            'Key_Type': 'GSI Range Key',
            'Description': 'Date when the threat intelligence was created'
        },
        {
            'Attribute_Name': 'geographic_region',
            'Type': 'String (S)',
            'Key_Type': 'GSI Hash Key',
            'Description': 'Geographic region associated with the threat'
        },
        {
            'Attribute_Name': 'ioc_type',
            'Type': 'String (S)',
            'Key_Type': 'GSI Hash Key',
            'Description': 'Type of Indicator of Compromise (IP, domain, hash, etc.)'
        },
        {
            'Attribute_Name': 'last_modified',
            'Type': 'String (S)',
            'Key_Type': 'GSI Range Key',
            'Description': 'Date when the threat intelligence was last modified'
        },
        {
            'Attribute_Name': 'pattern_hash',
            'Type': 'String (S)',
            'Key_Type': 'GSI Hash/Range Key',
            'Description': 'Hash of the threat pattern for deduplication'
        },
        {
            'Attribute_Name': 'risk_score',
            'Type': 'Number (N)',
            'Key_Type': 'GSI Range Key',
            'Description': 'Risk score associated with the threat'
        },
        {
            'Attribute_Name': 'source_name',
            'Type': 'String (S)',
            'Key_Type': 'GSI Hash Key',
            'Description': 'Name of the threat intelligence source (OTX, Abuse.ch, etc.)'
        },
        {
            'Attribute_Name': 'threat_type',
            'Type': 'String (S)',
            'Key_Type': 'GSI Hash Key',
            'Description': 'Type of threat (malware, phishing, etc.)'
        }
    ]

    # Add GSI information
    gsi_data = [
        {
            'Index_Name': 'ioc-pattern-index',
            'Hash_Key': 'ioc_type',
            'Range_Key': 'pattern_hash',
            'Projection': 'ALL',
            'Purpose': 'Query IOCs by type and pattern'
        },
        {
            'Index_Name': 'time-index',
            'Hash_Key': 'object_type',
            'Range_Key': 'created_date',
            'Projection': 'ALL',
            'Purpose': 'Query objects by type and creation time'
        },
        {
            'Index_Name': 'geographic-index',
            'Hash_Key': 'geographic_region',
            'Range_Key': 'confidence',
            'Projection': 'ALL',
            'Purpose': 'Query threats by geographic region and confidence'
        },
        {
            'Index_Name': 'risk-analytics-index',
            'Hash_Key': 'threat_type',
            'Range_Key': 'risk_score',
            'Projection': 'ALL',
            'Purpose': 'Analytics on threat types and risk scores'
        },
        {
            'Index_Name': 'temporal-correlation-index',
            'Hash_Key': 'object_type',
            'Range_Key': 'last_modified',
            'Projection': 'ALL',
            'Purpose': 'Track modifications by object type and time'
        },
        {
            'Index_Name': 'pattern-hash-index',
            'Hash_Key': 'pattern_hash',
            'Range_Key': 'N/A',
            'Projection': 'KEYS_ONLY',
            'Purpose': 'Deduplication queries by pattern hash'
        },
        {
            'Index_Name': 'source-index',
            'Hash_Key': 'source_name',
            'Range_Key': 'confidence',
            'Projection': 'ALL',
            'Purpose': 'Query threats by source and confidence level'
        }
    ]

    return pd.DataFrame(schema_data), pd.DataFrame(gsi_data)

def main():
    try:
        # Load DynamoDB scan data
        with open('dynamodb_data.json', 'r') as f:
            data = json.load(f)

        # Convert DynamoDB items to regular dictionaries
        items = [convert_dynamodb_to_dict(item) for item in data['Items']]

        # Create DataFrames
        data_df = pd.DataFrame(items)
        schema_df, gsi_df = create_schema_dataframe()

        # Create metadata DataFrame
        metadata = {
            'Property': [
                'Table Name',
                'Total Items',
                'Table Size (Bytes)',
                'Creation Date',
                'Billing Mode',
                'Table Status',
                'SSE Encryption',
                'Number of GSIs',
                'Export Timestamp'
            ],
            'Value': [
                'threat-intel-platform-threat-intelligence-dev',
                data['Count'],
                '69,025',
                '2025-10-31T08:17:29.857000-05:00',
                'PAY_PER_REQUEST',
                'ACTIVE',
                'KMS Enabled',
                '7',
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ]
        }
        metadata_df = pd.DataFrame(metadata)

        # Create Excel file with multiple sheets
        with pd.ExcelWriter('threat_intel_dynamodb_export.xlsx', engine='openpyxl') as writer:
            # Sheet 1: Table Metadata
            metadata_df.to_excel(writer, sheet_name='Table_Metadata', index=False)

            # Sheet 2: Attribute Schema
            schema_df.to_excel(writer, sheet_name='Attribute_Schema', index=False)

            # Sheet 3: Global Secondary Indexes
            gsi_df.to_excel(writer, sheet_name='GSI_Schema', index=False)

            # Sheet 4: All Data
            data_df.to_excel(writer, sheet_name='Threat_Intelligence_Data', index=False)

        print(f"✅ Successfully exported DynamoDB data to 'threat_intel_dynamodb_export.xlsx'")
        print(f"📊 Exported {len(items)} items across 4 sheets:")
        print(f"   - Table_Metadata: Table information and statistics")
        print(f"   - Attribute_Schema: Column definitions and descriptions")
        print(f"   - GSI_Schema: Global Secondary Index information")
        print(f"   - Threat_Intelligence_Data: All {len(items)} threat intelligence records")

        # Show data preview
        if not data_df.empty:
            print(f"\n📋 Data Preview (first 5 columns):")
            preview_cols = list(data_df.columns)[:5]
            print(data_df[preview_cols].head(3).to_string(index=False))

    except FileNotFoundError:
        print("❌ Error: dynamodb_data.json not found. Please run the DynamoDB scan first.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error creating Excel file: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()