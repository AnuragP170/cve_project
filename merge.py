import pandas as pd

def process_cvss_vectors(file_path, output_path):
    # Read the Excel file
    df = pd.read_excel(file_path)

    # # Initialize new columns
    # df['CVSS Version'] = None
    # df['CVSS vector string'] = None

    # Process each row according to the given conditions
    for index, row in df.iterrows():
        if pd.notna(row['CVSS2 Vector String']) and pd.isna(row['CVSS3 Vector String']):
            df.at[index, 'CVSS Version'] = 2
            df.at[index, 'CVSS vector string'] = row['CVSS2 Vector String']
        elif pd.isna(row['CVSS2 Vector String']) and pd.notna(row['CVSS3 Vector String']):
            df.at[index, 'CVSS Version'] = 3
            df.at[index, 'CVSS vector string'] = row['CVSS3 Vector String']
        elif pd.notna(row['CVSS2 Vector String']) and pd.notna(row['CVSS3 Vector String']):
            df.at[index, 'CVSS Version'] = 3
            df.at[index, 'CVSS vector string'] = row['CVSS3 Vector String']

    # Save the modified DataFrame to a new Excel file
    df.to_excel(output_path, index=False)

# Example usage
input_file_path = 'merged.xlsx'
output_file_path = 'merged_done.xlsx'
process_cvss_vectors(input_file_path, output_file_path)
