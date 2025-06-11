import json
import os


def entity_to_prolog(entity: dict) -> list[str]:
    predicates: list[str] = []

    name = entity["name"]

    predicates.append(f"{name}/1")

    fields = entity["fields"]

    for field in fields:
        field_name = field["name"]

        predicates.append(f"{field_name}/2")

    return predicates


if __name__ == "__main__":
    cwd = os.path.dirname(__file__)
    json_filepath = os.path.join(cwd, "schema.json")
    prolog_filepath = os.path.join(cwd, "schema.pl")

    with open(json_filepath, "r") as f:
        data = json.load(f)

    entities = data["entities"]

    clauses = [":- multifile\t\tedge/4.\n", ":- discontiguous\tedge/4.\n\n"]

    for entity in entities:
        predicates = entity_to_prolog(entity)

        clauses.extend(
            [f":- multifile\t\t{p}.\n:- discontiguous\t{p}.\n" for p in predicates]
        )

        clauses.append("\n")

    with open(prolog_filepath, "w") as f:
        f.writelines(clauses)