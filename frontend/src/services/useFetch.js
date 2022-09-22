import {useState} from "react";
const {useEffect} = require("react");

const useFetch = (url, options) => {

    const [data, setData] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [reFetchFlag, setReFetchFlag] = useState(0);

    const reFetch = () => {
        setReFetchFlag((prevState) => prevState + 1);
    }

    useEffect(() => {

        console.log('Im fetching!');
        const abortController = new AbortController();

        let fetchOptions = options;
        fetchOptions.signal = abortController.signal;

        console.log(fetchOptions);

        fetch(url, fetchOptions)
            .then(response => {
                if(!response.ok){
                    throw Error('Fetching data for that resource failed!');
                }
                return response.json();
            })
            .then(data => {
                setIsLoading(false);
                setData(data);
                console.log("Im in setData!");
                setError(null);
            })
            .catch(error => {
                console.log("Im in error! : " + error.message);
                if(!(error.name === 'AbortError')) {
                    setIsLoading(false);
                    setError(error.message);
                    setData(null);
                }
            });

        return () => abortController.abort();

    }, [url, reFetchFlag]);
    
    return{data, isLoading, error, reFetch}
}

export default useFetch;