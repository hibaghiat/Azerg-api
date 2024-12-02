from stix2 import (
    AttackPattern,
    Campaign,
    CourseOfAction,
    Grouping,
    Identity,
    Indicator,
    Infrastructure,
    IntrusionSet,
    Location,
    Malware,
    MalwareAnalysis,
    Note,
    ObservedData,
    Opinion,
    Relationship,
    Report,
    Sighting,
    ThreatActor,
    Tool,
    Vulnerability,
)


def get_pattern(key: str):
    mapping = {
        "DOMAIN": "domain-name",
        "IPv4": "ipv4-addr",
        "IPv6": "ipv6-addr",
        "FILE_HASH_SHA256": "file:hash.sha256",
        "FILE_HASH_SHA1": "file:hash.sha1",
        "FILE_HASH_MD5": "file:hash.md5",
        "URL": "url",
        "ASN": "asn",
        "EMAIL": "email-addr",
        "FILE_NAME": "file:name",
        "MAC_ADDRESS": "mac-addr",
        "WINDOWS_PATHS": "directory",
        "LINUX_PATHS": "directory",
        "REGISTRY_KEYS": "windows-registry-key",
    }
    return mapping[key]


def is_country(word):
    countries = [
        "Afghanistan",
        "Albania",
        "Algeria",
        "Andorra",
        "Angola",
        "Antigua and Barbuda",
        "Argentina",
        "Armenia",
        "Australia",
        "Austria",
        "Azerbaijan",
        "Bahamas",
        "Bahrain",
        "Bangladesh",
        "Barbados",
        "Belarus",
        "Belgium",
        "Belize",
        "Benin",
        "Bhutan",
        "Bolivia",
        "Bosnia and Herzegovina",
        "Botswana",
        "Brazil",
        "Brunei",
        "Bulgaria",
        "Burkina Faso",
        "Burundi",
        "Cabo Verde",
        "Cambodia",
        "Cameroon",
        "Canada",
        "Central African Republic",
        "Chad",
        "Chile",
        "China",
        "Colombia",
        "Comoros",
        "Congo, Democratic Republic of the",
        "Congo, Republic of the",
        "Costa Rica",
        "Croatia",
        "Cuba",
        "Cyprus",
        "Czech Republic",
        "Denmark",
        "Djibouti",
        "Dominica",
        "Dominican Republic",
        "Ecuador",
        "Egypt",
        "El Salvador",
        "Equatorial Guinea",
        "Eritrea",
        "Estonia",
        "Eswatini",
        "Ethiopia",
        "Fiji",
        "Finland",
        "France",
        "Gabon",
        "Gambia",
        "Georgia",
        "Germany",
        "Ghana",
        "Greece",
        "Grenada",
        "Guatemala",
        "Guinea",
        "Guinea-Bissau",
        "Guyana",
        "Haiti",
        "Honduras",
        "Hungary",
        "Iceland",
        "India",
        "Indonesia",
        "Iran",
        "Iraq",
        "Ireland",
        "Israel",
        "Italy",
        "Jamaica",
        "Japan",
        "Jordan",
        "Kazakhstan",
        "Kenya",
        "Kiribati",
        "Korea, North",
        "Korea, South",
        "Kosovo",
        "Kuwait",
        "Kyrgyzstan",
        "Laos",
        "Latvia",
        "Lebanon",
        "Lesotho",
        "Liberia",
        "Libya",
        "Liechtenstein",
        "Lithuania",
        "Luxembourg",
        "Madagascar",
        "Malawi",
        "Malaysia",
        "Maldives",
        "Mali",
        "Malta",
        "Marshall Islands",
        "Mauritania",
        "Mauritius",
        "Mexico",
        "Micronesia",
        "Moldova",
        "Monaco",
        "Mongolia",
        "Montenegro",
        "Morocco",
        "Mozambique",
        "Myanmar",
        "Namibia",
        "Nauru",
        "Nepal",
        "Netherlands",
        "New Zealand",
        "Nicaragua",
        "Niger",
        "Nigeria",
        "North Macedonia",
        "Norway",
        "Oman",
        "Pakistan",
        "Palau",
        "Panama",
        "Papua New Guinea",
        "Paraguay",
        "Peru",
        "Philippines",
        "Poland",
        "Portugal",
        "Qatar",
        "Romania",
        "Russia",
        "Rwanda",
        "Saint Kitts and Nevis",
        "Saint Lucia",
        "Saint Vincent and the Grenadines",
        "Samoa",
        "San Marino",
        "Sao Tome and Principe",
        "Saudi Arabia",
        "Senegal",
        "Serbia",
        "Seychelles",
        "Sierra Leone",
        "Singapore",
        "Slovakia",
        "Slovenia",
        "Solomon Islands",
        "Somalia",
        "South Africa",
        "South Sudan",
        "Spain",
        "Sri Lanka",
        "Sudan",
        "Suriname",
        "Sweden",
        "Switzerland",
        "Syria",
        "Taiwan",
        "Tajikistan",
        "Tanzania",
        "Thailand",
        "Timor-Leste",
        "Togo",
        "Tonga",
        "Trinidad and Tobago",
        "Tunisia",
        "Turkey",
        "Turkmenistan",
        "Tuvalu",
        "Uganda",
        "Ukraine",
        "United Arab Emirates",
        "United Kingdom",
        "United States",
        "Uruguay",
        "Uzbekistan",
        "Vanuatu",
        "Vatican City",
        "Venezuela",
        "Vietnam",
        "Yemen",
        "Zambia",
        "Zimbabwe",
        "Palestine",
    ]
    return word in countries


def get_entity_uuid(id, stix_objects):
    for obj in stix_objects:
        split_id = obj[0]["id"].split("--")
        split_id = split_id[1]
        if id == split_id:
            return obj[0]["id"]


def convert_to_stix_objects(data):
    stix_objects = []
    if hasattr(data, "name"):
        entity_type = data.type.lower()
        if entity_type == "attack_pattern":
            stix_objects.append(
                AttackPattern(
                    id=f"attack-pattern--{data.uuid}",
                    name=data.name,
                )
            )
        elif entity_type == "campaign":
            stix_objects.append(
                Campaign(
                    id=f"campaign--{data.uuid}",
                    name=data.name,
                )
            )
        elif entity_type == "course_of_action":
            stix_objects.append(
                CourseOfAction(
                    id=f"course-of-action--{data.uuid}",
                    name=data.name,
                )
            )
        elif entity_type == "grouping":
            stix_objects.append(
                Grouping(
                    id=f"grouping--{data.uuid}",
                    name=data.name,
                )
            )
        elif entity_type == "identity":
            stix_objects.append(
                Identity(
                    id=f"identity--{data.uuid}",
                    name=data.name,
                )
            )
        elif entity_type == "indicator":
            stix_objects.append(
                Indicator(
                    id=f"indicator--{data.uuid}",
                    name=data.name,
                    pattern="[{} = '{}']".format(data.pattern, data.name),
                    pattern_type="stix",
                )
            )
        elif entity_type == "infrastructure":
            stix_objects.append(
                Infrastructure(
                    id=f"infrastructure--{data.uuid}",
                    name=data.name,
                )
            )
        elif entity_type == "intrusion_set":
            stix_objects.append(
                IntrusionSet(
                    id=f"intrusion-set--{data.uuid}",
                    name=data.name,
                )
            )
        elif entity_type == "location":
            if is_country(word=data.name):
                stix_objects.append(
                    Location(
                        id=f"location--{data.uuid}", name=data.name, country=data.name
                    )
                )
            else:
                stix_objects.append(
                    Location(
                        id=f"location--{data.uuid}", name=data.name, region=data.name
                    )
                )
        elif entity_type == "malware":
            stix_objects.append(
                Malware(
                    id=f"malware--{data.uuid}",
                    name=data.name,
                    is_family=False,
                )
            )
        elif entity_type == "malware_analysis":
            stix_objects.append(
                MalwareAnalysis(
                    id=f"malware-analysis--{data.uuid}",
                    name=data.name,
                    analysis_type=data.analysis_type,
                )
            )
        elif entity_type == "note":
            stix_objects.append(Note(id=f"note--{data.uuid}", content=data.content))
        elif entity_type == "observed_data":
            stix_objects.append(
                ObservedData(
                    id=f"observed-data--{data.uuid}",
                    first_observed=data.first_observed,
                    last_observed=data.last_observed,
                    number_observed=data.number_observed,
                    objects=data.objects,
                )
            )
        elif entity_type == "opinion":
            stix_objects.append(
                Opinion(id=f"opinion--{data.uuid}", content=data.content)
            )
        elif entity_type == "report":
            stix_objects.append(
                Report(
                    id=f"report--{data.uuid}",
                    name=data.name,
                )
            )
        elif entity_type == "threat_actor":
            stix_objects.append(
                ThreatActor(
                    id=f"threat-actor--{data.uuid}",
                    name=data.name,
                )
            )
        elif entity_type == "tool":
            stix_objects.append(
                Tool(
                    id=f"tool--{data.uuid}",
                    name=data.name,
                )
            )
        elif entity_type == "vulnerability":
            stix_objects.append(
                Vulnerability(
                    id=f"vulnerability--{data.uuid}",
                    name=data.name,
                )
            )
    if hasattr(data, "relationship_type"):
        stix_objects.append(
            Relationship(
                id=f"relationship--{data.uuid}",
                relationship_type=data.relationship_type,
                source_ref=data.source_ref,
                target_ref=data.target_ref,
            )
        )
    return stix_objects
