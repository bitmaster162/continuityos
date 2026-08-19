from __future__ import annotations

import pytest

from continuityos.index import rank


def test_rank_rejects_query_candidate_dimension_mismatch():
    with pytest.raises(ValueError, match="vector dimension mismatch"):
        rank([1.0, 0.0, 0.0], [{"vec": [1.0, 0.0]}])


def test_rank_rejects_mixed_candidate_dimensions():
    with pytest.raises(ValueError, match="vector dimension mismatch"):
        rank(
            [1.0, 0.0, 0.0],
            [
                {"vec": [1.0, 0.0, 0.0]},
                {"vec": [1.0, 0.0]},
            ],
        )


def test_rank_accepts_exact_dimension_and_preserves_ordering():
    out = rank(
        [1.0, 0.0, 0.0],
        [
            {"id": "best", "vec": [1.0, 0.0, 0.0]},
            {"id": "other", "vec": [0.0, 1.0, 0.0]},
        ],
    )
    assert [row[1]["id"] for row in out] == ["best", "other"]


def test_rank_rejects_empty_query_vector_when_candidates_exist():
    with pytest.raises(ValueError, match="query vector must be non-empty"):
        rank([], [{"vec": [1.0]}])
