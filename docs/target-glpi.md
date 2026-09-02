# Target - GLPI

Supports saving scan reports as inventory natively within GLPI.

If a token is set, requires a user with permission to POST data and an authorization token generated for that user.
If toke is omitted, an anonymous inventory submission is attempted.

**Example**

```bash
network_discover --net=192.168.0.0/24 --format=glpi --glpi-url=glpi.yourdomain.tld --glpi-token=123456789abcdef --community public
```

## Requirements for GLPI

### Enable Inventory

Enable inventory intake by browsing to `Administration -> Inventory`.
(**GLPI 12 note**: Currently only unauthenticated and OAUTH are supported as auth methods.)

### Multitenant Assigning

For multitenant environments browse to `Administration -> Rules -> Rules for assigning an item to an entity`
and create a new rule under this category.

* Name: something meaningful to you, ie: "**Assign by Tag**"
* Active: **Yes**

Then once created, browse down to `Criteria` on the rule page and create a new criteria for the rule.

* Criteria: **Criteria - Inventory Tag**
* Type: **regular expression matches**
* Matches: **/^(.*)$/**

Then once criteria is added, browse down to `Actions` and add a new action

* Action: **Entity from TAG**
* Type: **Assign the value from regular expression**
* Value: **#0**

### Import by UUID

This network scanner generates a unique UUID based on the device MAC and manufacturer.
This allows the imported device to be tracked by this generated identifier, but must be enabled within GLPI.

Browse to `Administration -> Rules -> Rules for import and link equipments`

Add the following rules:

* Name: NetworkEquipment update (by UUID)
* Active: Yes
* Criteria #1: **Criteria - Asset > Item Type** | **is** | **Network device**
* Criteria #2: **Criteria - Asset > UUID** | **exists** | **Yes**
* Criteria #3: **Criteria - Asset > UUID** | **is already present** | **Yes**
* Action: **Actions - Inventory Link** | **Assign** | **Link if possible**

* Name: NetworkEquipment import (by UUID)
* Active: Yes
* Criteria #1: **Criteria - Asset > Item Type** | **is** | **Network device**
* Criteria #2: **Criteria - Asset > UUID** | **exists** | **Yes**
* Action: **Actions - Inventory Link** | **Assign** | **Link if possible**

Drag the rules to the appropriate location in the tree; group "update" rule with other updates and "import"
with other imports.

(_It may be necessary to save a rule once repositioned in the correct order to get the position to update_.)

Repeat the same 2 rules for **Phones** and **Printers** if necessary, replacing the names and type as necessary.


## Configuration Parameters

**glpi_credentials**

Optionally, you can include the default **SNMP Credentials** by adding the following to your configuration:

```yaml
override:
  - net: 10.200.0.0/24
    community: public
    glpi_credentials: 2
```

This is the ID of the SNMP credentials to link, as available from {glip_url}/front/snmpcredential.php.
Does not look up the credentials and still needs the community setting.

**glpi_tag**

You can also specify a tag to attribute each individual host or network.

```yaml
override:
  - net: 10.200.0.0/24
    glpi_tag: Some Client Name
```

**glpi_phone**

GLPI supports storing phones as actual Phone objects, (requires a patched version of GLPI).
To disable this support and save phones as standard NetworkEquipment instead, set the following in your config.

```yaml
override:
  - net: 10.200.0.0/24
    glpi_phone: False
```