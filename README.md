# `After Securing`

There are a number of considerations after adding the PII information and securing the data
1. In order to save the PII data to the account we need to use the new '/addInfo' endpoint with the details sent in the body in json format
   1. It is not required to send all potential datas, this works for any combination of the new fields (phone_number, disabilities, full_name, date_of_birth)
   2. The Disabilities need to be added in an array, while the rest of the fields should be a string (no checks were done on the input types)
```sh
localhost:4000/students/api/addInfo
{
    "phone_number": 1,
    "disabilities": ["adhd"],
    "full_name": "Jerry Moloney",
    "date_of_birth": "1/1/1970"
}
```
2. Then, when using the /user endpoint, this will show the email/display_name as previously, but also show any new PII that was added in the /addInfo section
3. In the Document for this assesment it is mentioned: 'the tests in run_test.py should continue to succeed ', however the test_login and test_login_case_insensitive were consistently failing for me
   1. Upon further review of these failures, it seems that in the setup of these tests the password is being directly inserted to the DB, resulting in the login process comparing a hashed version of the password (from the /login api call) to an unhashed version (from the test setup)
   2. I have updated the register function in the test/login.py to also hash the passwords prior to inserting into the DB in order for the test to be checking the same details
