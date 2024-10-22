#!/bin/bash

BUCKET_NAME="mylambdafunctions002"
REGION="us-east-1"
ZIP_FILES=("Generatetoken.zip" "Validatetoken.zip")
DIRECTORIES=("generate-token" "validate-token")

# Function to create an S3 bucket
create_bucket() {
    local bucket_name=$1
    local region=$2
    if aws s3api head-bucket --bucket "$bucket_name" 2>/dev/null; then
        echo "Bucket $bucket_name already exists."
    else
        if [ "$region" == "us-east-1" ]; then
            aws s3api create-bucket --bucket "$bucket_name" --region "$region"
        else
            aws s3api create-bucket --bucket "$bucket_name" --region "$region" --create-bucket-configuration LocationConstraint="$region"
        fi
        echo "Bucket $bucket_name created successfully."
    fi
}

# Function to zip directories using PowerShell
zip_files() {
    local directories=("${!1}")
    local zip_files=("${!2}")

    for i in "${!directories[@]}"; do
        local dir="${directories[$i]}"
        local zip_file="${zip_files[$i]}"

        if [ -d "$dir" ]; then
            powershell.exe -Command "Compress-Archive -Path '$dir/*' -DestinationPath '$zip_file'"
            echo "Directory $dir zipped as $zip_file."
        else
            echo "Directory $dir does not exist."
        fi
    done
}

# Function to upload files to S3 bucket
upload_file() {
    local bucket_name=$1
    local file_name=$2
    if [ -f "$file_name" ]; then
        aws s3 cp "$file_name" "s3://$bucket_name/"
        echo "File $file_name uploaded to s3://$bucket_name/"
    else
        echo "File $file_name does not exist."
    fi
}

# Main script
create_bucket "$BUCKET_NAME" "$REGION"
zip_files DIRECTORIES[@] ZIP_FILES[@]

for file in "${ZIP_FILES[@]}"; do
    upload_file "$BUCKET_NAME" "$file"
done
