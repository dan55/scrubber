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
from pyspark.sql.types import StringType
from awsglue.dynamicframe import DynamicFrame
# from pyspark.sql.functions import *

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
    

# def replace_cell(original_cell_value, sorted_reverse_start_end_tuples):
#     if sorted_reverse_start_end_tuples:
#         for entity in sorted_reverse_start_end_tuples:
#             to_mask_value = original_cell_value[entity[0] : entity[1]]
#             original_cell_value = original_cell_value.replace(to_mask_value, "###")
#     return original_cell_value


# def row_pii(column_name, original_cell_value, detected_entities):
#     if column_name in detected_entities.keys():
#         entities = detected_entities[column_name]
#         start_end_tuples = map(
#             lambda entity: (entity["start"], entity["end"]), entities
#         )
#         sorted_reverse_start_end_tuples = sorted(
#             start_end_tuples, key=lambda start_end: start_end[1], reverse=True
#         )
#         return replace_cell(original_cell_value, sorted_reverse_start_end_tuples)
#     return original_cell_value


# row_pii_udf = udf(row_pii, StringType())

# def recur(df, remaining_keys):
#     if len(remaining_keys) == 0:
#         return df
#     else:
#         head = remaining_keys[0]
#         tail = remaining_keys[1:]
#         modified_df = df.withColumn(
#             head, row_pii_udf(lit(head), head, "DetectedEntities")
#         )
#         return recur(modified_df, tail)


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

# Script generated for node Detect Sensitive Data
# entity_detector = EntityDetector()
# detected_df = entity_detector.detect(
#     dyf,
#     [
#         "PERSON_NAME",
#         "EMAIL",
#         "CREDIT_CARD",
#         "IP_ADDRESS",
#         "MAC_ADDRESS",
#         "PHONE_NUMBER",
#         "USA_PASSPORT_NUMBER",
#         "USA_SSN",
#         "USA_ITIN",
#         "BANK_ACCOUNT",
#         "USA_DRIVING_LICENSE",
#         "USA_HCPCS_CODE",
#         "USA_NATIONAL_DRUG_CODE",
#         "USA_NATIONAL_PROVIDER_IDENTIFIER",
#         "USA_DEA_NUMBER",
#         "USA_HEALTH_INSURANCE_CLAIM_NUMBER",
#         "USA_MEDICARE_BENEFICIARY_IDENTIFIER",
#         "JAPAN_BANK_ACCOUNT",
#         "JAPAN_DRIVING_LICENSE",
#         "JAPAN_MY_NUMBER",
#         "JAPAN_PASSPORT_NUMBER",
#         "UK_BANK_ACCOUNT",
#         "UK_BANK_SORT_CODE",
#         "UK_DRIVING_LICENSE",
#         "UK_ELECTORAL_ROLL_NUMBER",
#         "UK_NATIONAL_HEALTH_SERVICE_NUMBER",
#         "UK_NATIONAL_INSURANCE_NUMBER",
#         "UK_PASSPORT_NUMBER",
#         "UK_PHONE_NUMBER",
#         "UK_UNIQUE_TAXPAYER_REFERENCE_NUMBER",
#         "UK_VALUE_ADDED_TAX",
#     ],
#     "DetectedEntities",
# )

# keys = dyf.toDF().columns
# updated_masked_df = recur(detected_df.toDF(), keys)
# updated_masked_df = updated_masked_df.drop("DetectedEntities")

# DetectSensitiveData = DynamicFrame.fromDF(
#     updated_masked_df, glueContext, "updated_masked_df"
# )

# debug_dynamic_frame(DetectSensitiveData)

# Write data
glueContext.write_dynamic_frame.from_options(
    frame=DetectSensitiveData, #dyf_decrypted,
    connection_type="s3",
    format="json",
    connection_options={
        "path": "s3://bobo-scrubber-test-dest/dest/",
        "partitionKeys": [],
    },
    transformation_ctx="S3bucket_node3",
)

job.commit()
