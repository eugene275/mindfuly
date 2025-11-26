"""add mood logs and spotify sessions tables

Revision ID: 555a2535552b
Revises: 69170547b295
Create Date: 2025-11-17 02:06:05.023645

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '555a2535552b'
down_revision: Union[str, Sequence[str], None] = '69170547b295'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'mood_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('mood_value', sa.Integer(), nullable=False),
        sa.Column('energy_level', sa.Integer(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('weather', sa.String(100), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_mood_logs_id'), 'mood_logs', ['id'], unique=False)
    
    op.create_table(
        'spotify_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('track_name', sa.String(255), nullable=True),
        sa.Column('artist_name', sa.String(255), nullable=True),
        sa.Column('duration_minutes', sa.Float(), nullable=True),
        sa.Column('session_type', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_spotify_sessions_id'), 'spotify_sessions', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_spotify_sessions_id'), table_name='spotify_sessions')
    op.drop_table('spotify_sessions')
    op.drop_index(op.f('ix_mood_logs_id'), table_name='mood_logs')
    op.drop_table('mood_logs')



