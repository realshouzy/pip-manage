from __future__ import annotations

__all__: Final[tuple[str, ...]] = ("InteractiveAsker",)

from typing import Final


class InteractiveAsker:
    def __init__(self, prompt: str) -> None:
        self.prompt: str = prompt
        self.cached_answer: str | None = None
        self.last_answer: str | None = None

    def ask(self) -> str:
        if self.cached_answer is not None:
            return self.cached_answer

        question_default: str = f"{self.prompt} [Y]es, [N]o, [A]ll, [Q]uit "
        answer: str | None = ""
        while answer not in {"y", "n", "a", "q"}:
            question_last: str = (
                f"{self.prompt} [Y]es, [N]o, [A]ll, [Q]uit ({self.last_answer}) "
            )
            answer = (
                input(question_last if self.last_answer else question_default)
                .strip()
                .casefold()
            )
            answer = self.last_answer if answer == "" else answer

        if answer in {"q", "a"}:
            self.cached_answer = answer
        self.last_answer = answer

        return answer
