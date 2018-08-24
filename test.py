from sqlalchemy import create_engine

e = create_engine('sqlite:///database/evo_lution.db')

with open('hognose', 'r') as f:
	data = f.readlines()
	for item in data:
		print(item)
		e.execute("""insert into genes(name, breed) values(:name,:breed);""", name=item.rstrip(), breed=1)
print("done")