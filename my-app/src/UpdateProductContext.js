import { createContext, useState } from "react";

export const UpdateProductContext = createContext();

export const UpdateProductContextProvider = ({ children }) => {
  const [updateProductInfo, setUpdateProductInfo] = useState(null);

  return (
    <UpdateProductContext.Provider value={[updateProductInfo, setUpdateProductInfo]}>
      {children}
    </UpdateProductContext.Provider>
  );
};
