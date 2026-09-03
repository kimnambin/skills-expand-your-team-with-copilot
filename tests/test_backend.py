import unittest
from unittest.mock import patch

from fastapi import HTTPException

from src.backend import database
from src.backend.routers import activities, auth


class PasswordTests(unittest.TestCase):
    def test_hash_password_returns_verifiable_argon2_hash(self):
        hashed = database.hash_password("secret")

        self.assertNotEqual(hashed, "secret")
        self.assertTrue(hashed.startswith("$argon2"))


class AuthenticationTests(unittest.TestCase):
    def test_hash_password_is_deterministic_sha256(self):
        self.assertEqual(
            auth.hash_password("secret"),
            "2bb80d537b1da3e38bd30361aa855686bde0eacd"
            "7162fef6a25fe97bf527a25b",
        )

    @patch.object(auth, "teachers_collection")
    def test_login_returns_public_teacher_details(self, teachers):
        teachers.find_one.return_value = {
            "_id": "teacher",
            "username": "teacher",
            "display_name": "Ms. Teacher",
            "password": auth.hash_password("secret"),
            "role": "teacher",
        }

        self.assertEqual(
            auth.login("teacher", "secret"),
            {
                "username": "teacher",
                "display_name": "Ms. Teacher",
                "role": "teacher",
            },
        )

    @patch.object(auth, "teachers_collection")
    def test_login_rejects_invalid_credentials(self, teachers):
        teachers.find_one.return_value = None

        with self.assertRaisesRegex(HTTPException, "Invalid username or password"):
            auth.login("missing", "secret")

    @patch.object(auth, "teachers_collection")
    def test_check_session_rejects_unknown_teacher(self, teachers):
        teachers.find_one.return_value = None

        with self.assertRaisesRegex(HTTPException, "Teacher not found"):
            auth.check_session("missing")


class ActivityTests(unittest.TestCase):
    @patch.object(activities, "activities_collection")
    def test_get_activities_builds_filters_and_removes_ids(self, collection):
        collection.find.return_value = [
            {
                "_id": "Chess Club",
                "schedule_details": {"days": ["Monday"]},
                "participants": [],
            }
        ]

        result = activities.get_activities(
            day="Monday", start_time="15:00", end_time="17:00"
        )

        collection.find.assert_called_once_with(
            {
                "schedule_details.days": {"$in": ["Monday"]},
                "schedule_details.start_time": {"$gte": "15:00"},
                "schedule_details.end_time": {"$lte": "17:00"},
            }
        )
        self.assertEqual(result["Chess Club"]["participants"], [])
        self.assertNotIn("_id", result["Chess Club"])

    @patch.object(activities, "activities_collection")
    def test_get_available_days_returns_sorted_database_days(self, collection):
        collection.aggregate.return_value = [{"_id": "Friday"}, {"_id": "Monday"}]

        self.assertEqual(activities.get_available_days(), ["Friday", "Monday"])
        collection.aggregate.assert_called_once()

    @patch.object(activities, "teachers_collection")
    def test_signup_requires_teacher_authentication(self, teachers):
        with self.assertRaisesRegex(
            HTTPException, "Authentication required for this action"
        ):
            activities.signup_for_activity(
                "Chess Club", "student@example.com", teacher_username=None
            )

        teachers.find_one.assert_not_called()

    @patch.object(activities, "activities_collection")
    @patch.object(activities, "teachers_collection")
    def test_signup_adds_new_participant(self, teachers, collection):
        teachers.find_one.return_value = {"_id": "teacher"}
        collection.find_one.return_value = {
            "_id": "Chess Club",
            "participants": [],
        }
        collection.update_one.return_value.modified_count = 1

        result = activities.signup_for_activity(
            "Chess Club", "student@example.com", "teacher"
        )

        self.assertEqual(
            result, {"message": "Signed up student@example.com for Chess Club"}
        )
        collection.update_one.assert_called_once_with(
            {"_id": "Chess Club"},
            {"$push": {"participants": "student@example.com"}},
        )

    @patch.object(activities, "teachers_collection")
    @patch.object(activities, "activities_collection")
    def test_signup_rejects_duplicate_participant(self, collection, teachers):
        teachers.find_one.return_value = {"_id": "teacher"}
        collection.find_one.return_value = {
            "_id": "Chess Club",
            "participants": ["student@example.com"],
        }

        with self.assertRaisesRegex(HTTPException, "Already signed up"):
            activities.signup_for_activity(
                "Chess Club", "student@example.com", "teacher"
            )

    @patch.object(activities, "teachers_collection")
    @patch.object(activities, "activities_collection")
    def test_unregister_removes_existing_participant(self, collection, teachers):
        teachers.find_one.return_value = {"_id": "teacher"}
        collection.find_one.return_value = {
            "_id": "Chess Club",
            "participants": ["student@example.com"],
        }
        collection.update_one.return_value.modified_count = 1

        result = activities.unregister_from_activity(
            "Chess Club", "student@example.com", "teacher"
        )

        self.assertEqual(
            result,
            {"message": "Unregistered student@example.com from Chess Club"},
        )
        collection.update_one.assert_called_once_with(
            {"_id": "Chess Club"},
            {"$pull": {"participants": "student@example.com"}},
        )

    @patch.object(activities, "teachers_collection")
    @patch.object(activities, "activities_collection")
    def test_unregister_rejects_missing_participant(self, collection, teachers):
        teachers.find_one.return_value = {"_id": "teacher"}
        collection.find_one.return_value = {
            "_id": "Chess Club",
            "participants": [],
        }

        with self.assertRaisesRegex(HTTPException, "Not registered"):
            activities.unregister_from_activity(
                "Chess Club", "student@example.com", "teacher"
            )


if __name__ == "__main__":
    unittest.main()
