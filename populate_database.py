import pandas as pd
from sqlalchemy import create_engine, text
import logging
import pymysql
import urllib.parse

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database credentials
db_config = {
    'user': 'redacted',
    'password': 'redacted',
    'host': '54.79.198.148',
    'port': 3306,
    'database': 'Mitigation',
    'table': 'cve_data'
}
db_password_encoded = urllib.parse.quote_plus(db_config['password'])

# Function to create the database connection
def create_connection(use_db=False):
    try:
        if use_db:
            conn = pymysql.connect(user=db_config['user'], password=db_config['password'], host=db_config['host'], port=db_config['port'], database=db_config['database'])
        else:
            conn = pymysql.connect(user=db_config['user'], password=db_config['password'], host=db_config['host'], port=db_config['port'])
        logging.info("Database connection successful")
        return conn
    except Exception as e:
        logging.error(f"Error connecting to database: {e}")
        return None

# Function to check if a table exists
def table_exists(conn, db_name, table_name):
    try:
        use_db_query = f"USE {db_name};"
        with conn.cursor() as cursor:
            cursor.execute(use_db_query)
            cursor.execute(f"SHOW TABLES LIKE '{table_name}';")
            result = cursor.fetchone()
            logging.info(f"Table exists check result: {result}")
            return result is not None
    except Exception as e:
        logging.error(f"Error checking if table exists: {e}")
        return False

# Function to create the CVE table based on Excel columns
def create_cve_table(conn, db_name, table_name, columns):
    use_db_query = f"USE {db_name};"
    
    create_table_query = f"CREATE TABLE IF NOT EXISTS `{table_name}` ("
    column_definitions = ["`entry_id` INT AUTO_INCREMENT PRIMARY KEY"]
    
    for column_name in columns:
        sql_type = 'TEXT'  # Default to TEXT for simplicity
        if 'date' in column_name.lower():
            sql_type = 'DATETIME'
        
        if column_name == 'CVE ID':
            column_definitions.append(f"`{column_name.replace(' ', '_')}` VARCHAR(255) NULL")
        else:
            column_definitions.append(f"`{column_name.replace(' ', '_')}` {sql_type} NULL")
    
    create_table_query += ", ".join(column_definitions) + ", UNIQUE (`CVE_ID`(255)));"

    with conn.cursor() as cursor:
        cursor.execute(use_db_query)
        cursor.execute(create_table_query)
        conn.commit()
        logging.info(f"Table '{table_name}' created or already exists")

# Function to insert data into the CVE table using SQLAlchemy for bulk insertion
def insert_cve_data(engine, cve_data, table_name):
    try:
        # Standardize column names and remove entry_id if present
        cve_data.columns = [col.replace(' ', '_') for col in cve_data.columns]
        if 'entry_id' in cve_data.columns:
            cve_data.drop(columns=['entry_id'], inplace=True)

        # Replace NaN with None
        cve_data = cve_data.where(pd.notnull(cve_data), None)
        
        # Insert data into the database
        cve_data.to_sql(table_name, con=engine, if_exists='append', index=False)
        
        logging.info("Data has been successfully inserted into the database.")
    except Exception as e:
        logging.error(f"An error occurred while inserting data into the database: {e}")

# Function to count and print the number of entries in the table
def count_entries(engine, table_name):
    count_query = f"SELECT COUNT(*) FROM `{table_name}`;"
    try:
        with engine.connect() as conn:
            result = conn.execute(text(count_query))
            count = result.scalar()
            logging.info(f"Total number of entries in '{table_name}': {count}")
    except Exception as e:
        logging.error(f"Error counting entries: {e}")

# Main function to execute the process
def main():
    # Path to the CVE Excel file
    excel_file_path = 'processed_cve_data.xlsx'

    # Load the CVE data from Excel
    cve_data = pd.read_excel(excel_file_path)

    # Convert date columns to datetime with error handling
    for col in cve_data.columns:
        if 'date' in col.lower():
            cve_data[col] = pd.to_datetime(cve_data[col], errors='coerce')

    # Get column names
    columns = cve_data.columns

    # Print column names for debugging
    logging.info(f"Column names: {columns}")

    # Create the initial database connection using pymysql for dynamic table handling
    conn = create_connection(use_db=True)
    if conn:
        db_name = db_config['database']
        table_name = db_config['table']

        # Create the CVE table if it doesn't exist
        if not table_exists(conn, db_name, table_name):
            create_cve_table(conn, db_name, table_name, columns)
        conn.close()

    # Create SQLAlchemy engine for bulk insertion
    engine = create_engine(f'mysql+pymysql://{db_config["user"]}:{db_password_encoded}@{db_config["host"]}:{db_config["port"]}/{db_name}')
    logging.info("SQLAlchemy engine created successfully.")

    # Insert the CVE data using SQLAlchemy for bulk insertion
    insert_cve_data(engine, cve_data, table_name)

    # Count and print the number of entries
    count_entries(engine, table_name)

if __name__ == '__main__':
    main()
