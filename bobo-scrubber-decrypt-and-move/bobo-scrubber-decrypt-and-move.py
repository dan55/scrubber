import base64
import boto3
import json
import sys

from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from awsglueml.transforms import EntityDetector

from botocore.exceptions import ClientError
from py3rijndael import RijndaelCbc, ZeroPadding

def cast_notes_to_plaintext(dyf):
    dyf["notes_plaintext"] = dyf["notes_decrypted"].decode("utf-8")
    
    return dyf


def debug_dynamic_frame(dyf):
    dyf.printSchema()
    dyf.show()
    dyf.toDF().show()

    return None


def decrypt_notes(dyf):
    # Get encryption key
    enc_secret = get_secret()
    enc_key = json.loads(enc_secret)["MESSAGE_ENCRYPTION_SECRET"]
    
    iv = 'kByhT6PjYHzJzZfXvb8Aw5URMbQnk6NM+g3IV5siWD4='
    rijndael_cbc = RijndaelCbc(
        key=base64.b64decode(enc_key),
        iv=base64.b64decode(iv),
        padding=ZeroPadding(32),
        block_size=32
    )
    
    dyf["notes_decoded"] = base64.b64decode(dyf["notes_enc"])
    dyf["notes_decrypted"] = rijndael_cbc.decrypt(dyf["notes_decoded"])
    
    return dyf


def get_secret(secret_name="scrubber-enc-key", region_name="us-east-1"):

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response['SecretString']

    # Your code goes here.
    return secret


# Initialize job
args = getResolvedOptions(sys.argv, ["JOB_NAME"])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args["JOB_NAME"], args)

# Read data
dyf = glueContext.create_dynamic_frame.from_catalog(
    database="bobo-scrubber-test-db",
    table_name="bobo_scrubber_test"
)
debug_dynamic_frame(dyf)

# Decrypt notes
dyf_decrypted = dyf.map(f = decrypt_notes)
debug_dynamic_frame(dyf_decrypted)

# Convert to plaintext
dyf_notes = dyf_decrypted.map(f = cast_notes_to_plaintext)

# Drop some intermediate columns
dyf_notes =dyf_notes.drop_fields(paths=["notes_decoded", "notes_decrypted"])
debug_dynamic_frame(dyf_notes)

# Write data
glueContext.write_dynamic_frame.from_options(
    frame=dyf_decrypted,
    connection_type="s3",
    format="json",
    connection_options={
        "path": "s3://bobo-scrubber-test-dest/dest/",
        "partitionKeys": [],
    },
    transformation_ctx="S3bucket_node3",
)

job.commit()
