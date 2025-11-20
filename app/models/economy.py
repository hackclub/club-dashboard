"""
Economy and quest models for club token system.
Includes transactions, project submissions, weekly quests, and leaderboard exclusions.
"""
from datetime import datetime, timedelta, timezone
from flask import current_app
from extensions import db


class ClubTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # User who triggered the transaction
    transaction_type = db.Column(db.String(50), nullable=False)  # 'credit', 'debit', 'grant', 'purchase', 'refund', 'manual'
    amount = db.Column(db.Integer, nullable=False)  # Amount in tokens (positive for credits, negative for debits)
    description = db.Column(db.Text, nullable=False)
    balance_after = db.Column(db.Integer, nullable=False)  # Club balance after this transaction
    reference_id = db.Column(db.String(100), nullable=True)  # Reference to related record (project_id, order_id, etc.)
    reference_type = db.Column(db.String(50), nullable=True)  # 'project', 'shop_order', 'admin_action', etc.
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Admin who created the transaction

    club = db.relationship('Club', backref=db.backref('transactions', lazy=True, order_by='ClubTransaction.created_at.desc()', cascade='all, delete-orphan'))
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('club_transactions', lazy=True))
    created_by_user = db.relationship('User', foreign_keys=[created_by])

    def to_dict(self):
        return {
            'id': self.id,
            'club_id': self.club_id,
            'user_id': self.user_id,
            'transaction_type': self.transaction_type,
            'amount': self.amount,
            'description': self.description,
            'balance_after': self.balance_after,
            'reference_id': self.reference_id,
            'reference_type': self.reference_type,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by,
            'user': {
                'id': self.user.id,
                'username': self.user.username,
                'first_name': self.user.first_name,
                'last_name': self.user.last_name,
                'email': self.user.email
            } if self.user else None,
            'created_by_user': {
                'id': self.created_by_user.id,
                'username': self.created_by_user.username,
                'first_name': self.created_by_user.first_name,
                'last_name': self.created_by_user.last_name,
                'email': self.created_by_user.email
            } if self.created_by_user else None
        }


class ProjectSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('club_project.id'), nullable=True)  # Link to actual project if available
    project_name = db.Column(db.String(200), nullable=False)
    project_url = db.Column(db.String(500))
    submitted_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    approved_at = db.Column(db.DateTime)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('project_submissions', lazy=True))
    club = db.relationship('Club', backref=db.backref('project_submissions', lazy=True, cascade='all, delete-orphan'))
    project = db.relationship('ClubProject', backref=db.backref('submissions', lazy=True))
    approver = db.relationship('User', foreign_keys=[approved_by], backref=db.backref('approved_submissions', lazy=True))


class WeeklyQuest(db.Model):
    __tablename__ = 'weekly_quests'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    reward_tokens = db.Column(db.Integer, nullable=False)
    quest_type = db.Column(db.String(50), nullable=False)  # gallery_post, member_projects
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ClubQuestProgress(db.Model):
    __tablename__ = 'club_quest_progress'
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    quest_id = db.Column(db.Integer, db.ForeignKey('weekly_quests.id'), nullable=False)
    week_start = db.Column(db.Date, nullable=False)
    progress = db.Column(db.Integer, default=0)
    target = db.Column(db.Integer, nullable=False)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    reward_claimed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    club = db.relationship('Club', backref=db.backref('quest_progress', lazy=True, cascade='all, delete-orphan'))
    quest = db.relationship('WeeklyQuest', backref=db.backref('progress_records', lazy=True))

    __table_args__ = (db.UniqueConstraint('club_id', 'quest_id', 'week_start', name='_club_quest_week_uc'),)


class LeaderboardExclusion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'), nullable=False)
    leaderboard_type = db.Column(db.String(50), nullable=False)  # 'total_tokens', 'monthly_tokens', etc.
    excluded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    excluded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    reason = db.Column(db.Text)

    club = db.relationship('Club', backref=db.backref('leaderboard_exclusions', lazy=True, cascade='all, delete-orphan'))
    excluded_by_user = db.relationship('User', backref=db.backref('leaderboard_exclusions', lazy=True))


def create_club_transaction(club_id, transaction_type, amount, description, user_id=None, reference_id=None, reference_type=None, created_by=None):
    """Create a new club transaction and update the club balance"""
    try:
        from app.models.club import Club

        club = Club.query.filter_by(id=club_id).with_for_update().first()
        if not club:
            return False, "Club not found"

        if amount < 0 and club.tokens + amount < 0:
            return False, f"Insufficient balance. Current: {club.tokens} tokens, Required: {abs(amount)} tokens"

        club.tokens += amount
        club.balance = club.tokens / 100.0

        transaction = ClubTransaction(
            club_id=club_id,
            user_id=user_id,
            transaction_type=transaction_type,
            amount=amount,
            description=description,
            balance_after=club.tokens,
            reference_id=reference_id,
            reference_type=reference_type,
            created_by=created_by
        )

        db.session.add(transaction)
        db.session.commit()

        return True, transaction
    except Exception as e:
        db.session.rollback()
        return False, str(e)


def get_current_week_start():
    """Get the start of the current week (Monday)"""
    today = datetime.now().date()
    days_since_monday = today.weekday()
    week_start = today - timedelta(days=days_since_monday)
    return week_start


def update_quest_progress(club_id, quest_type, increment=1):
    """Update quest progress for a club"""
    try:
        from app.models.club import Club

        week_start = get_current_week_start()

        quest = WeeklyQuest.query.filter_by(quest_type=quest_type, is_active=True).first()
        if not quest:
            return False, "Quest not found"

        target = 1 if quest_type == 'gallery_post' else 5

        progress_record = ClubQuestProgress.query.filter_by(
            club_id=club_id,
            quest_id=quest.id,
            week_start=week_start
        ).first()

        if not progress_record:
            progress_record = ClubQuestProgress(
                club_id=club_id,
                quest_id=quest.id,
                week_start=week_start,
                progress=0,
                target=target,
                completed=False,
                reward_claimed=False
            )
            db.session.add(progress_record)

        progress_record.progress += increment
        progress_record.updated_at = datetime.utcnow()

        if progress_record.progress >= target and not progress_record.completed:
            progress_record.completed = True
            progress_record.completed_at = datetime.utcnow()

            club = Club.query.filter_by(id=club_id).with_for_update().first()
            if not club:
                current_app.logger.error(f"Club {club_id} not found when completing quest")
                return False, "Club not found"

            if club.piggy_bank_tokens >= quest.reward_tokens:
                club.piggy_bank_tokens -= quest.reward_tokens

                success, transaction = create_club_transaction(
                    club_id=club_id,
                    transaction_type='credit',
                    amount=quest.reward_tokens,
                    description=f'Weekly quest reward: {quest.name} (transferred from piggy bank)',
                    reference_type='weekly_quest',
                    reference_id=str(quest.id),
                    created_by=None
                )

                if success:
                    try:
                        piggy_success, piggy_transaction = create_club_transaction(
                            club_id=club_id,
                            transaction_type='piggy_bank_debit',
                            amount=-quest.reward_tokens,
                            description=f'Piggy bank deduction for quest reward: {quest.name}',
                            reference_type='weekly_quest',
                            reference_id=str(quest.id),
                            created_by=None
                        )
                        if piggy_success:
                            progress_record.reward_claimed = True
                            current_app.logger.info(f"Club {club_id} completed quest {quest.name} and received {quest.reward_tokens} tokens from piggy bank (remaining piggy bank: {club.piggy_bank_tokens})")
                        else:
                            current_app.logger.error(f"Failed to record piggy bank debit transaction: {piggy_transaction}")
                            progress_record.reward_claimed = True
                    except Exception as piggy_error:
                        current_app.logger.error(f"Error recording piggy bank transaction: {str(piggy_error)}")
                        progress_record.reward_claimed = True
                else:
                    club.piggy_bank_tokens += quest.reward_tokens
                    current_app.logger.error(f"Failed to award quest tokens: {transaction}")
            else:
                current_app.logger.warning(f"Club {club_id} completed quest {quest.name} but piggy bank has insufficient tokens ({club.piggy_bank_tokens} < {quest.reward_tokens}). No reward given.")
                progress_record.reward_claimed = False

        db.session.commit()
        return True, "Quest progress updated"

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating quest progress: {str(e)}")
        return False, str(e)
