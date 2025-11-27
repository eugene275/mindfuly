from fastapi import Depends, HTTPException
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float, insert, select, func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from collections import defaultdict
import calendar

from src.shared.database import get_db

from user_service_v2.models.user import Base, get_user_repository_v2, UserRepositoryV2

class MoodLog(Base):
    __tablename__ = "mood_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    mood_value = Column(Integer, nullable=False)
    energy_level = Column(Integer, nullable=False)
    notes = Column(Text, nullable=True)
    weather = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class MoodLogRepositoryV2():
    """
    Controls manipulation of the mood_logs table
    """

    def __init__(self, session):
        self.session = session
    
    # Create a new mood log entry
    async def create_mood_log(self,
                                user_id: int,
                                mood_value: int,
                                energy_level: int,
                                notes: Optional[str] = None,
                                weather: Optional[str] = None) -> MoodLog:

        try:
            self.session.execute(insert(MoodLog), [{
                "user_id": user_id,
                "mood_value": mood_value,
                "energy_level": energy_level,
                "notes": notes,
                "weather": weather
            }])
            self.session.commit()
            return MoodLog(
                user_id=user_id,
                mood_value=mood_value,
                energy_level=energy_level,
                notes=notes,
                weather=weather
            )
        except IntegrityError:
            self.session.rollback()
            return None
        
    # Edit latest mood log entry for a user (can only edit mood_value, energy_level, notes)
    async def edit_latest_mood_log(self,
                                    user_id: int,
                                    mood_value: Optional[int] = None,
                                    energy_level: Optional[int] = None,
                                    notes: Optional[str] = None):
        latest_log = await self.get_latest_mood_log(user_id)
        if not latest_log:
            return None
        
        if mood_value is not None:
            latest_log.mood_value = mood_value
        if energy_level is not None:
            latest_log.energy_level = energy_level
        if notes is not None:
            latest_log.notes = notes
        self.session.commit()
        return latest_log
        
    # Get the date of the most recent mood log for a user
    async def get_most_recent_log_date(self, user_id: int) -> Optional[datetime]:
        result = self.session.execute(
            select(MoodLog.created_at).where(MoodLog.user_id == user_id).order_by(MoodLog.created_at.desc()).limit(1)
        )
        
        most_recent = result.scalar_one_or_none()
        return most_recent
    
    # Get the latest mood log for a user
    async def get_latest_mood_log(self, user_id: int) -> Optional[MoodLog]:
        result = self.session.execute(
            select(MoodLog).where(MoodLog.user_id == user_id).order_by(MoodLog.created_at.desc()).limit(1)
        )
        mood_log = result.scalar_one_or_none()
        return mood_log
    
    # Get all mood logs for a user, limited by 'limit'
    async def get_mood_logs(self, user_id: int, limit: int = 10) -> list[MoodLog]:
        result = self.session.execute(
            select(MoodLog).where(MoodLog.user_id == user_id).order_by(MoodLog.created_at.desc()).limit(limit)
        )
        mood_logs = result.scalars().all()

        return sorted(mood_logs, key=lambda log: log.created_at, reverse=True)

    # Get average mood, energy level, and total logs for a user
    async def get_mood_stats(self, user_id: int) -> dict:
        result = self.session.execute(
            select(
                func.avg(MoodLog.mood_value).label("avg_mood"),
                func.avg(MoodLog.energy_level).label("avg_energy"),
                func.count(MoodLog.id).label("total_logs")
            ).where(MoodLog.user_id == user_id)
        )

        stats = result.first()

        return {
            "avg_mood": round(float(stats.avg_mood or 0), 2),
            "avg_energy": round(float(stats.avg_energy or 0), 2),
            "total_logs": stats.total_logs or 0
        }
    
    # Get average mood, energy level, and total logs for all days of a week
    async def get_weekly_mood_stats(self, user_id: int) -> list[dict]:
        """
        Get stats based on the days of the week

        Example:
        Monday: avg_mood, avg_energy, total_logs
        Tuesday: avg_mood, avg_energy, total_logs
        ...
        """

        result = self.session.execute(
            select(MoodLog).where(MoodLog.user_id == user_id)
        )
        logs = result.scalars().all()

        weekday_groups = defaultdict(list)

        for log in logs:
            weekday_number = log.created_at.weekday()
            weekday_name = calendar.day_name[weekday_number]
            weekday_groups[weekday_name].append(log)

        weekly_stats = []

        for day, logs_for_day in weekday_groups.items():
            if len(logs_for_day) == 0:
                continue

            avg_mood = sum(log.mood_value for log in logs_for_day) / len(logs_for_day)
            avg_energy = sum(log.energy_level for log in logs_for_day) / len(logs_for_day)
            total_logs = len(logs_for_day)

            weekly_stats.append({
                "day": day,
                "avg_mood": avg_mood,
                "avg_energy": avg_energy,
                "total_logs": total_logs,
            })

        return weekly_stats
    
    # Get average mood, energy level, and total logs for each weather condition
    async def get_weather_mood_stats(self, user_id: int) -> list[dict]:
        """
        Get stats based on weather conditions

        Example:
        Sunny: avg_mood, avg_energy, total_logs
        Rainy: avg_mood, avg_energy, total_logs
        ...
        """

        result = self.session.execute(
            select(
                MoodLog.weather,
                func.avg(MoodLog.mood_value).label("avg_mood"),
                func.avg(MoodLog.energy_level).label("avg_energy"),
                func.count(MoodLog.id).label("total_logs")
            ).where(
                (MoodLog.user_id == user_id) &
                (MoodLog.weather.isnot(None)) &
                (MoodLog.weather != "")
            )
            .group_by(MoodLog.weather)
            .order_by(MoodLog.weather)
        )

        weather_stats = []

        for entry in result.all():
            weather_stats.append({
                "weather": entry.weather,
                "avg_mood": round(float(entry.avg_mood or 0), 2),
                "avg_energy": round(float(entry.avg_energy or 0), 2),
                "total_logs": entry.total_logs or 0
            })

        return weather_stats
    
    # Calculate running means for mood and energy levels for each day
    async def get_running_means(self, user_id: int, limit: int = 20) -> list[dict]:
        """
        Average mood and energy aggregated by day, ordered by most recent date.
        For example, the average on 2024-10-01 would be the mean of all mood and energy logs
        created on and before 2024-10-01.
        """

        result = self.session.execute(
            select(
                func.date(MoodLog.created_at).label("log_date"),
                func.avg(MoodLog.mood_value).label("avg_mood"),
                func.avg(MoodLog.energy_level).label("avg_energy")
            ).where(MoodLog.user_id == user_id)
            .group_by(func.date(MoodLog.created_at))
            .order_by(func.date(MoodLog.created_at).desc())
            .limit(limit)
        )

        daily_averages = result.all()

        running_means = []
        cumulative_mood = 0.0
        cumulative_energy = 0.0
        total_days = 0

        for entry in daily_averages:
            total_days += 1
            cumulative_mood += float(entry.avg_mood or 0)
            cumulative_energy += float(entry.avg_energy or 0)

            running_mean_mood = round(cumulative_mood / total_days, 2)
            running_mean_energy = round(cumulative_energy / total_days, 2)

            running_means.append({
                "date": entry.log_date.isoformat(),
                "avg_mood": running_mean_mood,
                "avg_energy": running_mean_energy
            })

        return running_means
    
    # Clear all mood logs for a user (for testing purposes)
    async def clear_mood_logs(self, user_id: int):
        self.session.execute(
            MoodLog.__table__.delete().where(MoodLog.user_id == user_id)
        )

        self.session.commit()

def get_mood_log_repository_v2(db: Session = Depends(get_db)) -> MoodLogRepositoryV2:
    return MoodLogRepositoryV2(db)

class MoodLogCreate(BaseModel):
    username: str
    mood_value: int
    energy_level: int
    notes: Optional[str] = None
    weather: Optional[str] = None

class MoodLogResponse(BaseModel):
    user_id: int
    mood_value: int
    energy_level: int
    notes: Optional[str]
    weather: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

    @classmethod
    def from_db_model(cls, mood_log: MoodLog) -> "MoodLogResponse":
        return cls(
            user_id=mood_log.user_id,
            mood_value=mood_log.mood_value,
            energy_level=mood_log.energy_level,
            notes=mood_log.notes,
            weather=mood_log.weather,
            created_at=datetime.utcnow()  # or mood_log.created_at if you want the original timestamp
        )