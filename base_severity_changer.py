import pandas as pd

# Define the setBaseSeverity function
def setBaseSeverity(base_score, base_severity):
    if base_score != 'N/A' and base_severity == 'N/A' or base_severity == '':
        base_score = float(base_score)
        if 0.1 <= base_score <= 3.9:
            base_severity = 'Low'
        elif 4.0 <= base_score <= 6.9:
            base_severity = 'Medium'
        elif 7.0 <= base_score <= 8.9:
            base_severity = 'High'
        elif 9.0 <= base_score <= 10:
            base_severity = 'Critical'
    return base_severity

# Function to update the Excel file
def update_base_severity(input_file, output_file):
    # Read the Excel file
    df = pd.read_excel(input_file)

    # Iterate through each row and update the "Base Severity" column
    for index, row in df.iterrows():
        base_score = row['Base Score']
        base_severity = row['Base Severity']
        new_severity = setBaseSeverity(base_score, base_severity)
        df.at[index, 'Base Severity'] = new_severity

    # Save the updated DataFrame to a new Excel file
    df.to_excel(output_file, index=False)

# Example usage
input_file = 'all_cve_data.xlsx'  # Replace with your input Excel file
output_file = 'all_cve_data_2.xlsx'  # Replace with your desired output Excel file
update_base_severity(input_file, output_file)
