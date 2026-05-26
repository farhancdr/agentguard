#!/bin/bash
# hooks/block-aws.sh
#
# Blocks all `aws` CLI invocations except:
#   1. Read-only identity checks:
#        aws sts get-caller-identity
#        aws configure list
#        aws configure list-profiles
#   2. DynamoDB read ops (get-item, query, scan, batch-get-item, describe-table)
#      whose --table-name argument matches one of the allow-listed tables.
#
# Allowed tables: defaults to dev_asset_table, dev_analytic_table,
# dev_global_player_table. Override by setting AGENTGUARD_AWS_ALLOWED_TABLES
# to a comma-separated list, e.g.:
#   export AGENTGUARD_AWS_ALLOWED_TABLES="dev_asset_table,dev_other_table"
#
# Matching strategy: each statement (separated by ; && || | $( ) is checked
# independently so an `aws` call hiding inside a pipeline is still caught.
# A leading `echo "aws ..."` is NOT triggered — only invocations at a
# statement boundary count.
#
# Exit 2 = blocked. Exit 0 = allowed.

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.command // .tool_input.command // ""') || exit 0

# Statement-boundary prefix for aws invocations. Mirrors block-main-branch.sh.
_AWS_STMT='(^|[;&|]|\$\()[[:space:]]*(sudo[[:space:]]+)?aws[[:space:]]+'

# Quick exit: no aws invocation at any statement boundary
if ! echo "$COMMAND" | grep -qE "${_AWS_STMT}"; then
  exit 0
fi

# Build allowed-tables alternation regex.
# Split on commas, strip whitespace, drop empty entries, escape regex metachars,
# join with |.
_raw_tables="${AGENTGUARD_AWS_ALLOWED_TABLES:-dev_asset_table,dev_analytic_table,dev_global_player_table}"
TABLES_RE=$(echo "$_raw_tables" | tr ',' '\n' \
  | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
  | grep -v '^$' \
  | sed 's/[.^$*+?()[\]\\|{}]/\\&/g' \
  | awk '{printf "%s%s", sep, $0; sep="|"} END{print ""}')

READ_OPS='(get-item|query|scan|batch-get-item|describe-table)'

# Word-edge marker: any non-identifier char, or end-of-line.
# Used to anchor matches like `get-caller-identity` so trailing `)` or `;`
# doesn't slip through, but `--table-name=dev_asset_table_extra` doesn't
# accidentally match `dev_asset_table`.
_WB='([^a-zA-Z0-9_-]|$)'

_block_generic() {
  echo "Blocked: aws CLI access to remote environment is restricted." >&2
  echo "Allowed invocations:" >&2
  echo "  aws sts get-caller-identity" >&2
  echo "  aws configure list / list-profiles" >&2
  echo "  aws dynamodb {get-item|query|scan|batch-get-item|describe-table} --table-name <allowed>" >&2
  echo "Allowed tables: $_raw_tables" >&2
}

# Iterate every aws invocation in the command. We split on shell separators
# (; && || | and the leading $( of command substitution) so each segment can
# be validated independently.
while IFS= read -r call; do
  # Trim leading whitespace and an optional leading sudo prefix.
  call_trim=$(echo "$call" | sed -E 's/^[[:space:]]*//;s/^sudo[[:space:]]+//')

  # Skip segments that don't start with aws (awk RS leaves all segments).
  echo "$call_trim" | grep -qE '^aws[[:space:]]+' || continue

  # 1. Identity: aws sts get-caller-identity
  if echo "$call_trim" | grep -qE "^aws[[:space:]]+sts[[:space:]]+get-caller-identity${_WB}"; then
    continue
  fi

  # 2. Identity: aws configure list / list-profiles
  if echo "$call_trim" | grep -qE "^aws[[:space:]]+configure[[:space:]]+list(-profiles)?${_WB}"; then
    continue
  fi

  # 3. DynamoDB read on allow-listed table
  if echo "$call_trim" | grep -qE "^aws[[:space:]]+dynamodb[[:space:]]+${READ_OPS}${_WB}"; then
    # Must carry --table-name <allowed>  (or --table-name=<allowed>)
    if echo "$call_trim" | grep -qE "(^|[[:space:]])--table-name[[:space:]=]+(${TABLES_RE})${_WB}"; then
      continue
    fi
    echo "Blocked: DynamoDB read on disallowed table." >&2
    echo "Allowed tables: $_raw_tables" >&2
    exit 2
  fi

  # Anything else: deny
  _block_generic
  exit 2
done < <(echo "$COMMAND" | awk 'BEGIN { RS = "[;&|]|[$][(]" } { print }')

exit 0
