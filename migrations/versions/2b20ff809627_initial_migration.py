"""Initial migration.

Revision ID: 2b20ff809627
Revises: 
Create Date: 2024-06-29 16:34:57.033596

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2b20ff809627'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('url_mapping',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('short_url', sa.String(length=6), nullable=False),
    sa.Column('long_url', sa.String(length=2048), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('short_url')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('url_mapping')
    # ### end Alembic commands ###
