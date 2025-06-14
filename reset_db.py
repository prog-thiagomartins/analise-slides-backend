from app.core.config import engine
from app.models.user import Base

if __name__ == "__main__":
    print("Dropando e recriando todas as tabelas...")
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("Pronto!")
