import zipfile
import os

def prepare_tool():
    # Unzip Models.zip
    with zipfile.ZipFile('Models.zip', 'r') as zip_ref:
        zip_ref.extractall('Models')

    print("Preparation complete.")

if __name__ == "__main__":
    prepare_tool()
