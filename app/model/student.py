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
    schools: List[School] = Field(default_factory=list)
    sat_profile: SATProfile = Field(default_factory=SATProfile)
    act_profile: ACTProfile = Field(default_factory=ACTProfile)


# -----------------------------------
# Course Work
# -----------------------------------

class Course(BaseModel):
    course_name: str
    subject: str
    level: str
    grade_achieved: str


class CourseWork(BaseModel):
    completed_courses: List[Course] = Field(default_factory=list)
    current_courses: List[Course] = Field(default_factory=list)


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
    preferred_fields_of_study: List[str] = Field(default_factory=list)
    career_interests: List[str] = Field(default_factory=list)


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
    preferred_colleges: List[str] = Field(default_factory=list)
    importance_factors: List[ImportanceFactor] = Field(default_factory=list)
    additional_questions: AdditionalQuestions = Field(default_factory=AdditionalQuestions)


# -----------------------------------
# Student Model
# -----------------------------------

class Student(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")

    # relation with User
    user_id: PyObjectId

    academic_profile: AcademicProfile = Field(default_factory=AcademicProfile)

    course_work: CourseWork = Field(default_factory=CourseWork)

    extra_curriculars: List[ExtraCurricular] = Field(default_factory=list)

    career_goals: CareerGoals = Field(default_factory=CareerGoals)

    college_preferences: CollegePreferences = Field(default_factory=CollegePreferences)

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
