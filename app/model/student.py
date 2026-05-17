from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime, timezone, date
from bson import ObjectId

from app.utils.py_object_id import PyObjectId


# -----------------------------------
# Academic Profile
# -----------------------------------

class School(BaseModel):
    school_name: str
    graduation_year: int
    state: str
    current_grade: str
    school_curriculum: str
    current_gpa: float
    gpa_scale: float


class SATProfile(BaseModel):
    attended: bool = False
    score: Optional[int] = None


class ACTProfile(BaseModel):
    attended: bool = False
    score: Optional[int] = None


class AcademicProfile(BaseModel):
    schools: List[School] = []
    sat_profile: SATProfile = SATProfile()
    act_profile: ACTProfile = ACTProfile()


# -----------------------------------
# Course Work
# -----------------------------------

class Course(BaseModel):
    course_name: str
    subject: str
    level: str
    grade_achieved: str


class CourseWork(BaseModel):
    completed_courses: List[Course] = []
    current_courses: List[Course] = []


# -----------------------------------
# Extra Curricular Activities
# -----------------------------------

class ExtraCurricular(BaseModel):
    activity: str
    role: str
    type: str
    start_date: date
    end_date: Optional[date] = None
    accomplishments: Optional[str] = None


# -----------------------------------
# Career Goals
# -----------------------------------

class CareerGoals(BaseModel):
    preferred_fields_of_study: List[str] = []
    career_interests: List[str] = []


# -----------------------------------
# College Preferences
# -----------------------------------

class ImportanceFactor(BaseModel):
    index: int
    name: str


class AdditionalQuestions(BaseModel):
    first_generation_college_student: bool = False
    needs_financial_aid: bool = False
    strong_in_state_preference: bool = False
    interested_in_competitive_sports: bool = False


class CollegePreferences(BaseModel):
    preferred_colleges: List[str] = []
    importance_factors: List[ImportanceFactor] = []
    additional_questions: AdditionalQuestions = AdditionalQuestions()


# -----------------------------------
# Student Model
# -----------------------------------

class Student(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")

    # relation with User
    user_id: PyObjectId

    academic_profile: AcademicProfile = AcademicProfile()

    course_work: CourseWork = CourseWork()

    extra_curriculars: List[ExtraCurricular] = []

    career_goals: CareerGoals = CareerGoals()

    college_preferences: CollegePreferences = CollegePreferences()

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
    )