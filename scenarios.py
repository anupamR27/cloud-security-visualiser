import json
from pathlib import Path

from models import Scenario


SCENARIOS_DIRECTORY = Path(__file__).parent / "data" / "scenarios"
SCENARIO_FILES = {
    "secure": "secure.json",
    "vulnerable": "vulnerable.json",
}


def load_scenario(scenario_id: str) -> Scenario:
    try:
        filename = SCENARIO_FILES[scenario_id]
    except KeyError as error:
        raise ValueError(f"Unknown scenario: {scenario_id}") from error

    with (SCENARIOS_DIRECTORY / filename).open(encoding="utf-8") as scenario_file:
        scenario_data = json.load(scenario_file)

    return Scenario.model_validate(scenario_data)
