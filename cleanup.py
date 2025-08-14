def find_automic_instances(ec2, name_prefixes=None):
    if name_prefixes is None:
        name_prefixes = ["automic-", "AEDB", "AE", "AWI"]
    resp = ec2.describe_instances(
        Filters=[{"Name": "tag:Name", "Values": name_prefixes}]
    )
    return resp
