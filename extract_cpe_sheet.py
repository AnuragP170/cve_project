# import pandas as pd
# import re
#
# def extract_platform_version(cell_value):
#     if isinstance(cell_value, str):
#         # Define regex pattern to extract platform and version
#         pattern = r'criteria:\s*cpe:[^:]+:[^:]+:[^:]+:(?P<platform>[^:]+):(?P<version>[^:]+)'
#
#         matches = re.findall(pattern, cell_value)
#         if matches:
#             return ', '.join([f"{platform} {version}" for platform, version in matches])
#     return 'N/A'
#
#
# def process_excel_file(input_filename, output_filename):
#     # Read the Excel file
#     df = pd.read_excel(input_filename)
#     print("read excel file")
#
#     # Check if the "Affected Platform" column exists
#     if 'Affected Platform' not in df.columns:
#         print("The 'Affected Platform' column is not found in the Excel file.")
#         return
#
#     # Apply the extraction function to the "Affected Platform" column
#     df['Platform Version'] = df['Affected Platform'].apply(extract_platform_version)
#
#     print("saving to excel file")
#     # Save the updated dataframe to a new Excel file
#     df.to_excel(output_filename, index=False)
#     print(f"Processed data saved to {output_filename}")
#
#
# if __name__ == "__main__":
#     input_filename = 'all_cve_data_2.xlsx'
#     output_filename = 'processed_cve_data.xlsx'
#     process_excel_file(input_filename, output_filename)

import pandas as pd


def fill_empty_cells(input_filename, output_filename):
    try:
        # Read the Excel file
        df = pd.read_excel(input_filename, usecols="A:K", nrows=242350)

        # Convert all columns to string type to avoid dtype issues
        df = df.astype(str)

        # Fill all empty cells with "N/A"
        df.fillna("N/A", inplace=True)

        # Save the updated dataframe back to an Excel file
        df.to_excel(output_filename, index=False)
        print(f"Processed data saved to {output_filename}")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    input_filename = 'processed_cve_data.xlsx'  # Replace with your input file name
    output_filename = 'processed_cve_data.xlsx'  # Replace with your desired output file name
    fill_empty_cells(input_filename, output_filename)
