"""remove_spotify_sessions_table

Revision ID: 8e5f0c4bc987
Revises: 555a2535552b
Create Date: 2025-11-26 01:19:26.921160

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8e5f0c4bc987'
down_revision: Union[str, Sequence[str], None] = '555a2535552b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_index(op.f('ix_spotify_sessions_id'), table_name='spotify_sessions', if_exists=True)
    op.drop_table('spotify_sessions')


def downgrade() -> None:
    """Downgrade schema."""
    op.create_table(
        'spotify_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('track_name', sa.String(255), nullable=True),
        sa.Column('artist_name', sa.String(255), nullable=True),
        sa.Column('duration_minutes', sa.Float(), nullable=True),
        sa.Column('session_type', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_spotify_sessions_id'), 'spotify_sessions', ['id'], unique=False)

